<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\Accessors\KeyRingHandle;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyDestination;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\KeyGenerated;
use RoundlyConsulting\Sentinel\Events\KeyRetired;
use RoundlyConsulting\Sentinel\Events\KeyRevoked;
use RoundlyConsulting\Sentinel\Events\KeyRotated;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\UnknownKeyException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;

function http(): KeyRingHandle
{
    return Sentinel::keys()->ring('http');
}

it('generates and stores a database key for every allowed algorithm (§10 item 34)', function (Algorithm $algorithm): void {
    Event::fake([KeyGenerated::class]);

    $generated = http()->generate($algorithm, label: 'partner');

    expect($generated->info->status)->toBe(KeyStatus::Active)
        ->and($generated->info->driver)->toBe('database')
        ->and($generated->info->label)->toBe('partner')
        ->and($generated->envSnippet)->toBeNull()
        ->and($generated->info->keyId)->toMatch('/^http-\d{8}-[a-z0-9]{6}$/')
        ->and($generated->publicKey === null)->toBe($algorithm->isHmac())
        ->and(Key::query()->where('kid', $generated->info->keyId)->value('envelope'))->not->toContain('base64:');

    $stored = app(KeyStoreManager::class)->find('http', $generated->info->keyId);
    $signature = (new Signers)->sign($stored, Purpose::Seal, 'm');

    expect((new Signers)->verify($stored, Purpose::Seal, 'm', $signature))->toBeTrue();

    Event::assertDispatched(KeyGenerated::class, static fn (KeyGenerated $event): bool => $event->algorithm === $algorithm && $event->ring === 'http');
})->with([Algorithm::HmacSha256, Algorithm::Ed25519, Algorithm::EcdsaP256Sha256, Algorithm::EcdsaP384Sha384]);

it('prints environment lines for a config destination and stores nothing', function (): void {
    $generated = Sentinel::keys()->ring()->generate(Algorithm::Ed25519, 'fresh-key', KeyDestination::Config);

    expect($generated->info->driver)->toBe('config')
        ->and($generated->envSnippet)->toStartWith("SENTINEL_KEY_ID=fresh-key\nSENTINEL_ALGORITHM=ed25519\nSENTINEL_KEY=\"base64:")
        ->and($generated->envSnippet)->toContain('SENTINEL_PUBLIC_KEY="'.$generated->publicKey.'"')
        ->and(Key::query()->count())->toBe(0);

    preg_match('/SENTINEL_KEY="(base64:[^"]+)"/', (string) $generated->envSnippet, $m);

    expect(KeyMaterial::fromEncoded(Algorithm::Ed25519, $m[1])->encodedPublic())->toBe($generated->publicKey);

    $http = http()->generate(Algorithm::HmacSha256, 'partner-1', KeyDestination::Config);

    expect($http->envSnippet)->toStartWith('SENTINEL_HTTP_KEY_ID=partner-1')->not->toContain('PUBLIC_KEY');
});

it('refuses algorithms outside the ring, taken and invalid key ids, and long labels', function (): void {
    http()->generate(Algorithm::HmacSha256, 'taken');

    expect(fn () => http()->generate(Algorithm::HmacSha384))->toThrow(AlgorithmNotAllowedException::class, '[http]')
        ->and(fn () => http()->generate(Algorithm::HmacSha256, 'taken'))->toThrow(KeyDriverException::class, 'already has a key [taken]')
        ->and(fn () => http()->generate(Algorithm::HmacSha256, "bad\nkid"))->toThrow(KeyDriverException::class)
        ->and(fn () => http()->generate(Algorithm::HmacSha256, label: str_repeat('x', 192)))->toThrow(KeyDriverException::class, '191')
        ->and(fn () => Sentinel::keys()->ring()->generate(Algorithm::HmacSha256))->toThrow(KeyDriverException::class, 'no database driver');
});

it('stores the owner and a scheduled activation', function (): void {
    $owner = User::query()->create(['name' => 'Partner']);
    $at = CarbonImmutable::parse('2030-01-01 12:00:00', 'Europe/Bratislava');

    $generated = http()->generate(Algorithm::Ed25519, 'scheduled', activatesAt: $at, owner: $owner);

    expect($generated->info->status)->toBe(KeyStatus::Pending)
        ->and($generated->info->activatesAt?->format('Y-m-d H:i:s e'))->toBe('2030-01-01 11:00:00 UTC')
        ->and($generated->info->ownerType)->toBe(User::class)
        ->and(Key::query()->firstOrFail()->activates_at->format('Y-m-d H:i:s.u e'))->toBe('2030-01-01 11:00:00.000000 UTC');
});

it('rotates a database ring: the old key stops signing when the new one activates', function (): void {
    Event::fake([KeyRotated::class]);
    $first = http()->generate(Algorithm::Ed25519, 'first');

    Carbon::setTestNow(CarbonImmutable::now()->addMinute());
    $result = http()->rotate();

    expect($result->previous?->keyId)->toBe('first')
        ->and($result->previous?->status)->toBe(KeyStatus::VerifyOnly)
        ->and($result->current->algorithm)->toBe(Algorithm::Ed25519)
        ->and($result->envSnippet)->toBeNull()
        ->and(http()->current()->keyId)->toBe($result->current->keyId)
        ->and(http()->find('first')?->status)->toBe(KeyStatus::VerifyOnly)
        ->and($first->info->keyId)->toBe('first');

    Event::assertDispatched(KeyRotated::class, static fn (KeyRotated $event): bool => $event->previousKeyId === 'first');
    Carbon::setTestNow();
});

it('rotates into a scheduled key: the old key signs until then', function (): void {
    http()->generate(Algorithm::HmacSha256, 'first');

    $result = http()->rotate(Algorithm::HmacSha256, CarbonImmutable::now()->addHour());

    expect($result->current->status)->toBe(KeyStatus::Pending)
        ->and(http()->current()->keyId)->toBe('first')
        ->and(http()->find('first')?->signsUntil?->equalTo($result->current->activatesAt))->toBeTrue();
});

/**
 * Chat review C-15: a rotation demotes every key of the ring that could still sign — a pending
 * one from an earlier scheduled rotation too — so only one key ever signs.
 */
it('demotes every older active or pending key when it rotates', function (): void {
    http()->generate(Algorithm::HmacSha256, 'k-a');
    $scheduled = http()->rotate(Algorithm::HmacSha256, CarbonImmutable::now()->addDay());

    $result = http()->rotate(Algorithm::HmacSha256);
    $at = $result->current->activatesAt;

    expect($result->previous?->keyId)->toBe('k-a')
        ->and(http()->find('k-a')?->signsUntil?->lessThanOrEqualTo($at))->toBeTrue()
        ->and(http()->find($scheduled->current->keyId)?->signsUntil?->lessThanOrEqualTo($at))->toBeTrue()
        ->and(Key::query()->where('ring', 'http')->whereNull('signs_until')->pluck('kid')->all())->toBe([$result->current->keyId]);

    // The scheduled key never takes over, and a later revocation brings no old key back.
    Carbon::setTestNow(CarbonImmutable::now()->addDays(2));

    expect(http()->current()->keyId)->toBe($result->current->keyId)
        ->and(http()->find($scheduled->current->keyId)?->status)->toBe(KeyStatus::VerifyOnly);

    http()->revoke($result->current->keyId, 'compromised');
    app(KeyStoreManager::class)->flush();

    expect(fn () => http()->current())->toThrow(NoSigningKeyException::class);
    Carbon::setTestNow();
});

it('rotates an empty database ring into its first key', function (): void {
    $result = http()->rotate(Algorithm::EcdsaP384Sha384);

    expect($result->previous)->toBeNull()->and(http()->current()->algorithm)->toBe(Algorithm::EcdsaP384Sha384);
});

it('rotates a config ring by printing the new key and the verify-only list', function (): void {
    config()->set('sentinel.keys.rings.default.previous', 'ancient|hmac-sha256|base64:'.base64_encode(random_bytes(32)));

    $result = Sentinel::keys()->ring()->rotate();

    expect($result->current->driver)->toBe('config')
        ->and($result->previous?->keyId)->toBe('test-default')
        ->and($result->previous?->status)->toBe(KeyStatus::VerifyOnly)
        ->and($result->envSnippet)->toContain("SENTINEL_KEY_ID={$result->current->keyId}")
        ->and($result->envSnippet)->toMatch('/SENTINEL_PREVIOUS_KEYS="ancient\|hmac-sha256\|base64:[^,"]+,test-default\|hmac-sha256\|base64:AQIDBAUG/');

    config()->set('sentinel.keys.rings.default.key', null);
    app(KeyStoreManager::class)->flush();

    expect(Sentinel::keys()->ring()->rotate(Algorithm::Ed25519)->previous)->toBeNull();
});

/**
 * Apply printed environment lines to the default ring's configuration, as an operator would.
 */
function applyEnvSnippet(string $snippet): void
{
    $keys = ['SENTINEL_KEY_ID' => 'key_id', 'SENTINEL_ALGORITHM' => 'algorithm', 'SENTINEL_KEY' => 'key', 'SENTINEL_PUBLIC_KEY' => 'public_key', 'SENTINEL_PREVIOUS_KEYS' => 'previous'];

    foreach (explode("\n", $snippet) as $line) {
        [$name, $value] = explode('=', $line, 2);
        config()->set('sentinel.keys.rings.default.'.$keys[$name], trim($value, '"'));
    }

    app(KeyStoreManager::class)->flush();
}

/**
 * Chat review C-9: an HMAC key has no public half, so the old one must be cleared.
 */
it('clears the public key when a config ring rotates from an asymmetric key to HMAC', function (): void {
    $ed = KeyMaterial::generate(Algorithm::Ed25519);
    config()->set('sentinel.keys.rings.default.key_id', 'ed-1');
    config()->set('sentinel.keys.rings.default.algorithm', 'ed25519');
    config()->set('sentinel.keys.rings.default.key', $ed->encodedPrivate());
    config()->set('sentinel.keys.rings.default.public_key', $ed->encodedPublic());
    app(KeyStoreManager::class)->flush();
    $before = invoice();

    $result = Sentinel::keys()->ring()->rotate(Algorithm::HmacSha256);
    applyEnvSnippet((string) $result->envSnippet);

    expect($result->envSnippet)->toContain("\nSENTINEL_PUBLIC_KEY=\n")
        ->and(Sentinel::keys()->ring()->current()->keyId)->toBe($result->current->keyId)
        ->and(Sentinel::keys()->ring()->current()->algorithm)->toBe(Algorithm::HmacSha256)
        ->and(Sentinel::verify(invoice())->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($before)->status)->toBe(VerificationStatus::Intact);
});

it('refuses to rotate into a disallowed algorithm', function (): void {
    expect(fn () => http()->rotate(Algorithm::HmacSha512))->toThrow(AlgorithmNotAllowedException::class);
});

it('revokes a database key after commit with its reason and actor', function (): void {
    Event::fake([KeyRevoked::class]);
    $actor = User::query()->create(['name' => 'Admin']);
    http()->generate(Algorithm::HmacSha256, 'leaked');

    DB::transaction(function () use ($actor): void {
        $info = http()->revoke('leaked', '  Leaked in a log  ', $actor);

        expect($info->status)->toBe(KeyStatus::Revoked)->and($info->revokedAt)->not->toBeNull();
        Event::assertNotDispatched(KeyRevoked::class);
    });

    Event::assertDispatched(KeyRevoked::class, static fn (KeyRevoked $event): bool => $event->reason === 'Leaked in a log' && $event->actorId === $actor->getKey());

    expect(Key::query()->value('revocation_reason'))->toBe('Leaked in a log')
        ->and(fn () => http()->current())->toThrow(NoSigningKeyException::class);
});

it('refuses revocations without a reason, of unknown or config keys, and across rings', function (): void {
    http()->generate(Algorithm::HmacSha256, 'partner');

    expect(fn () => http()->revoke('partner', '   '))->toThrow(KeyDriverException::class, 'reason')
        ->and(fn () => http()->revoke('partner', str_repeat('x', 1001)))->toThrow(KeyDriverException::class, 'reason')
        ->and(fn () => http()->revoke('nope', 'x'))->toThrow(UnknownKeyException::class, '[nope]')
        ->and(fn () => Sentinel::keys()->ring()->revoke('partner', 'x'))->toThrow(UnknownKeyException::class)
        ->and(fn () => Sentinel::keys()->ring()->revoke('test-default', 'x'))->toThrow(KeyDriverException::class, 'configuration');
});

it('retires a database key: it neither signs nor verifies afterwards', function (): void {
    Event::fake([KeyRetired::class]);
    http()->generate(Algorithm::HmacSha256, 'old');

    $info = http()->retire('old');

    expect($info->status)->toBe(KeyStatus::Retired)
        ->and(http()->find('old')?->status)->toBe(KeyStatus::Retired)
        ->and(fn () => http()->retire('nope'))->toThrow(UnknownKeyException::class)
        ->and(fn () => Sentinel::keys()->ring()->retire('test-default'))->toThrow(KeyDriverException::class);

    Event::assertDispatched(KeyRetired::class);
});

it('keeps an earlier end of verification when retiring', function (): void {
    Key::factory()->ring('http')->create(['kid' => 'k', 'verifies_until' => CarbonImmutable::now()->subDay()]);

    expect(http()->retire('k')->verifiesUntil?->lessThan(CarbonImmutable::now()->subHour()))->toBeTrue();
});

it('exposes the ring through the accessor and the manager', function (): void {
    expect(Sentinel::keys()->rings())->toBe(['default', 'http'])
        ->and(Sentinel::keys()->ring()->name())->toBe('default')
        ->and(Sentinel::keys()->all())->toHaveCount(1)
        ->and(Sentinel::keys()->ring()->all()[0]->keyId)->toBe('test-default')
        ->and(Sentinel::currentKey()->keyId)->toBe('test-default')
        ->and(Sentinel::findKey('default', 'nope'))->toBeNull()
        ->and(Sentinel::keys()->ring()->find('test-default')?->canSign)->toBeTrue();
});
