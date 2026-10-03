<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Events\KeyIntegrityViolated;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Keys\KeyEnvelope;
use RoundlyConsulting\Sentinel\Keys\KeyLookup;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\StorageCipher;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;
use RoundlyConsulting\Testing\Database\DriverMatrix;

function httpKeys(): KeyStoreManager
{
    $manager = app(KeyStoreManager::class);
    $manager->flush();

    return $manager;
}

it('signs with the newest active key that may sign', function (): void {
    Key::factory()->ring('http')->create(['kid' => 'older', 'activates_at' => Clock::now()->subDays(2)]);
    Key::factory()->ring('http')->create(['kid' => 'newer', 'activates_at' => Clock::now()->subDay()]);
    Key::factory()->ring('http')->pending()->create(['kid' => 'future']);
    Key::factory()->ring('http')->verifyOnly()->create(['kid' => 'verify-only', 'activates_at' => Clock::now()]);

    expect(httpKeys()->signingKey('http')->keyId)->toBe('newer');
});

it('has no signing key when every key is past signing', function (): void {
    Key::factory()->ring('http')->create(['signs_until' => Clock::now()->subSecond()]);

    expect(fn () => httpKeys()->signingKey('http'))->toThrow(NoSigningKeyException::class);
});

it('resolves the effective status of every lifecycle state (§10 item 10)', function (array $state, KeyStatus $status): void {
    Key::factory()->ring('http')->create(['kid' => 'k', ...$state]);

    expect(httpKeys()->find('http', 'k')?->status)->toBe($status);
})->with([
    'active' => [[], KeyStatus::Active],
    'pending' => [['activates_at' => CarbonImmutable::now()->addHour()], KeyStatus::Pending],
    'verify-only by date' => [['signs_until' => CarbonImmutable::now()->subMinute()], KeyStatus::VerifyOnly],
    'verify-only by state' => [['status' => 'verify_only'], KeyStatus::VerifyOnly],
    'retired by date' => [['verifies_until' => CarbonImmutable::now()->subMinute()], KeyStatus::Retired],
    'retired by state' => [['status' => 'retired'], KeyStatus::Retired],
    'revoked' => [['status' => 'revoked', 'revoked_at' => CarbonImmutable::now()], KeyStatus::Revoked],
    'unknown manual state' => [['status' => 'bogus'], KeyStatus::Revoked],
]);

it('lets the configured revocation list beat a restored "active" envelope', function (): void {
    // A full row (columns + authentic old envelope) restored from a backup passes the
    // integrity check — §3.2 #15. SENTINEL_REVOKED_KEYS always wins.
    Key::factory()->ring('http')->create(['kid' => 'restored']);
    config()->set('sentinel.keys.revoked', 'http:restored');

    expect(httpKeys()->find('http', 'restored')?->status)->toBe(KeyStatus::Revoked)
        ->and(fn () => httpKeys()->signingKey('http'))->toThrow(NoSigningKeyException::class);
});

it('detects every out-of-band edit of a key row (§10 item 11)', function (Closure $tamper): void {
    Event::fake([KeyIntegrityViolated::class]);
    $key = Key::factory()->ring('http')->create(['kid' => 'victim']);

    // false: the engine refused to store the corruption at all (MySQL rejects a bad datetime).
    if ($tamper($key) === false) {
        expect(DriverMatrix::driver())->not->toBe('sqlite');

        return;
    }

    expect(httpKeys()->lookup('http', 'victim'))->toEqual(new KeyLookup(null, KeyLookup::INTEGRITY));

    Event::assertDispatched(KeyIntegrityViolated::class, static fn (KeyIntegrityViolated $event): bool => $event->ring === 'http' && $event->keyId === 'victim' && $event->driver === 'database');
})->with([
    'algorithm column swapped' => [fn (Key $key) => Key::query()->whereKey($key->id)->update(['algorithm' => 'hmac-sha512'])],
    'status flipped without re-encrypting' => [fn (Key $key) => Key::query()->whereKey($key->id)->update(['status' => 'verify_only'])],
    'activation moved' => [fn (Key $key) => Key::query()->whereKey($key->id)->update(['activates_at' => '2000-01-01 00:00:00.000000'])],
    'revocation date injected' => [function (Key $key): void {
        Key::query()->whereKey($key->id)->update(['revoked_at' => '2026-01-01 00:00:00.000000']);
    }],
    'owner re-pointed' => [fn (Key $key) => Key::query()->whereKey($key->id)->update(['owner_type' => 'user', 'owner_id' => 7])],
    'garbage envelope' => [fn (Key $key) => Key::query()->whereKey($key->id)->update(['envelope' => 'not-a-ciphertext'])],
    'corrupt date column' => [fn (Key $key): bool => corrupt(static fn () => Key::query()->whereKey($key->id)->update(['activates_at' => 'yesterday']))],
    'envelope of another key' => [function (Key $key): void {
        $other = Key::factory()->ring('http')->create(['kid' => 'other']);
        Key::query()->whereKey($key->id)->update(['envelope' => $other->getRawOriginal('envelope')]);
    }],
    'public key replaced (same kid, other material)' => [function (Key $key): void {
        $forged = Key::factory()->ring('http')->ed25519()->make(['kid' => 'victim']);
        Key::query()->whereKey($key->id)->update(['algorithm' => 'ed25519', 'envelope' => $forged->envelope]);
    }],
    'valid JSON with a wrong shape' => [function (Key $key): void {
        $envelope = app(StorageCipher::class)->encrypt(StorageCipher::KEY_ENVELOPE, '{"v":"sentinel.key/1"}', KeyEnvelope::associatedData(Key::query()->findOrFail($key->id)));
        Key::query()->whereKey($key->id)->update(['envelope' => $envelope]);
    }],
    'unsupported algorithm inside the envelope' => [function (Key $key): void {
        $cipher = app(StorageCipher::class);
        $row = Key::query()->findOrFail($key->id);
        $plain = str_replace('"alg":"hmac-sha256"', '"alg":"none"', $cipher->decrypt(StorageCipher::KEY_ENVELOPE, (string) $row->envelope, KeyEnvelope::associatedData($row)));
        Key::query()->whereKey($key->id)->update(['algorithm' => 'none']);
        $envelope = $cipher->encrypt(StorageCipher::KEY_ENVELOPE, $plain, KeyEnvelope::associatedData(Key::query()->findOrFail($key->id)));
        Key::query()->whereKey($key->id)->update(['envelope' => $envelope]);
    }],
    'envelope minted by the application encrypter (dual-review O-3)' => [function (Key $key): void {
        $row = Key::query()->findOrFail($key->id);
        $plain = app(StorageCipher::class)->decrypt(StorageCipher::KEY_ENVELOPE, (string) $row->envelope, KeyEnvelope::associatedData($row));
        Key::query()->whereKey($key->id)->update(['envelope' => app('encrypter')->encryptString($plain)]);
    }],
]);

it('still opens envelopes after an APP_KEY rotation (previous keys)', function (): void {
    Key::factory()->ring('http')->create(['kid' => 'k']);

    $previous = config('app.key');
    $current = 'base64:'.base64_encode(Encrypter::generateKey('aes-256-cbc'));
    config()->set('app.key', $current);
    config()->set('app.previous_keys', [$previous]);
    app()->forgetInstance('encrypter');

    expect(httpKeys()->find('http', 'k')?->status)->toBe(KeyStatus::Active);
});

it('round-trips owner, label and material of a stored key', function (): void {
    $owner = User::query()->create(['name' => 'Ada']);
    $key = Key::factory()->ring('http')->ecdsaP256()->create(['kid' => 'owned', 'label' => 'Partner A', 'owner_type' => $owner->getMorphClass(), 'owner_id' => $owner->getKey()]);

    $resolved = httpKeys()->find('http', 'owned');

    expect($resolved?->ownerType)->toBe(User::class)
        ->and($resolved?->ownerId)->toBe('1')
        ->and($resolved?->label)->toBe('Partner A')
        ->and($resolved?->algorithm())->toBe(Algorithm::EcdsaP256Sha256)
        ->and($resolved?->canSign())->toBeTrue()
        ->and($key->owner)->toBeInstanceOf(User::class)
        ->and($key->toArray())->not->toHaveKey('envelope');
});
