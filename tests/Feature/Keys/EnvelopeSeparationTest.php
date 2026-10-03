<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\Canonical\Jcs;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Events\KeyIntegrityViolated;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\KeyIntegrityException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyEnvelope;
use RoundlyConsulting\Sentinel\Keys\KeyLookup;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\StorageCipher;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;

/**
 * Key envelopes are encrypted under their own key, derived from APP_KEY for that purpose only,
 * with the row's identity as associated data — never with the application encrypter, whose
 * ciphertexts any `encrypted` cast a host lets users write would mint or reveal.
 */

/**
 * The JCS plaintext of an envelope whose material the attacker chose.
 */
function attackerEnvelope(string $ring, string $kid, string $status, CarbonImmutable $at, ?string $owner = null): string
{
    return Jcs::encode([
        'activates_at' => Clock::iso($at), 'alg' => 'hmac-sha256', 'kid' => $kid,
        'material' => 'base64:'.base64_encode(random_bytes(32)), 'owner' => $owner, 'public' => null, 'revoked_at' => null,
        'ring' => $ring, 'signs_until' => null, 'status' => $status, 'v' => 'sentinel.key/1', 'verifies_until' => null,
    ]);
}

it('never accepts an envelope minted through a host encrypted cast as a signing key (dual-review O-3)', function (): void {
    Event::fake([KeyIntegrityViolated::class]);
    config()->set('sentinel.keys.rings.default.driver', 'database');
    config()->set('sentinel.keys.rings.default.key', null);
    config()->set('sentinel.keys.rings.default.key_id', null);
    app(KeyStoreManager::class)->flush();
    Sentinel::keys()->ring('default')->generate(Algorithm::HmacSha256, keyId: 'legit');
    app(KeyStoreManager::class)->flush();

    // The oracle: the app encrypts a user-supplied string through an `encrypted` cast.
    $at = Clock::now()->subMinute();
    $carrier = invoice(['secret' => attackerEnvelope('default', 'evil', 'active', $at)]);
    DB::table('sentinel_keys')->insert([
        'ring' => 'default', 'kid' => 'evil', 'algorithm' => 'hmac-sha256', 'status' => 'active',
        'envelope' => DB::table('invoices')->where('id', $carrier->getKey())->value('secret'),
        'activates_at' => Clock::database($at),
    ]);
    app(KeyStoreManager::class)->flush();

    expect(app(KeyStoreManager::class)->lookup('default', 'evil'))->toEqual(new KeyLookup(null, KeyLookup::INTEGRITY))
        ->and(app(KeyStoreManager::class)->signingKey('default')->keyId)->toBe('legit');

    Event::assertDispatched(KeyIntegrityViolated::class, static fn (KeyIntegrityViolated $event): bool => $event->keyId === 'evil');
});

it('never lets a planted envelope impersonate a partner on the http ring (dual-review O-3)', function (): void {
    $partner = User::query()->create(['name' => 'ACME']);
    $at = Clock::now()->subMinute();
    $plaintext = attackerEnvelope('http', 'acme-2026', 'verify_only', $at, $partner->getMorphClass().':'.$partner->getKey());

    DB::table('sentinel_keys')->insert([
        'ring' => 'http', 'kid' => 'acme-2026', 'algorithm' => 'hmac-sha256', 'status' => 'verify_only',
        'envelope' => Crypt::encryptString($plaintext), 'activates_at' => Clock::database($at),
        'owner_type' => $partner->getMorphClass(), 'owner_id' => $partner->getKey(),
    ]);

    // The attacker signs with the material it chose.
    $material = json_decode($plaintext, true)['material'];
    partnerRing('acme-2026', material: $material);
    $signed = Sentinel::signatures()->sign(new PsrRequest('POST', 'https://api.example.com/events', ['Content-Type' => 'application/json'], '{"event":"refund"}'), 'acme-2026');
    config()->set('sentinel.keys.rings.http.driver', 'database');
    app(KeyStoreManager::class)->flush();

    try {
        Sentinel::signatures()->verify(received($signed));
        $outcome = 'accepted';
    } catch (HttpSignatureException $exception) {
        $outcome = $exception->reason();
    }

    expect($outcome)->toBe(SignatureRejection::UnknownKey);
});

it('never decrypts an envelope through the application encrypter (dual-review O-3)', function (): void {
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: 'outbound');
    $envelope = (string) DB::table('sentinel_keys')->where('ring', 'http')->where('kid', 'outbound')->value('envelope');

    // A DB writer copies the envelope into a column the app decrypts for display.
    $mine = invoice(['secret' => 'my iban']);
    DB::table('invoices')->where('id', $mine->getKey())->update(['secret' => $envelope]);

    expect(fn () => Crypt::decryptString($envelope))->toThrow(DecryptException::class)
        ->and(fn () => Invoice::query()->findOrFail($mine->getKey())->secret)->toThrow(DecryptException::class)
        ->and($envelope)->not->toContain('material');
});

it('binds an envelope to its purpose and to the row it was written for (dual-review O-3)', function (): void {
    $cipher = app(StorageCipher::class);
    $sealed = $cipher->encrypt(StorageCipher::KEY_ENVELOPE, 'secret', 'row a');

    expect($cipher->decrypt(StorageCipher::KEY_ENVELOPE, $sealed, 'row a'))->toBe('secret')
        ->and(fn () => $cipher->decrypt(StorageCipher::KEY_ENVELOPE, $sealed, 'row b'))->toThrow(DecryptException::class)
        ->and(fn () => $cipher->decrypt(StorageCipher::IDEMPOTENT_RESPONSE, $sealed, 'row a'))->toThrow(DecryptException::class)
        ->and(fn () => $cipher->decrypt(StorageCipher::KEY_ENVELOPE, Crypt::encryptString('secret'), 'row a'))->toThrow(DecryptException::class)
        ->and(fn () => $cipher->decrypt(StorageCipher::KEY_ENVELOPE, 'sentinel:aes-256-gcm:not base64!', 'row a'))->toThrow(DecryptException::class)
        ->and($sealed)->not->toBe($cipher->encrypt(StorageCipher::KEY_ENVELOPE, 'secret', 'row a'));

    $key = Key::factory()->ring('http')->create(['kid' => 'bound']);
    $other = Key::factory()->ring('http')->create(['kid' => 'other']);
    Key::query()->whereKey($other->id)->update(['envelope' => $key->getRawOriginal('envelope')]);

    expect(app(KeyStoreManager::class)->lookup('http', 'other'))->toEqual(new KeyLookup(null, KeyLookup::INTEGRITY));
});

it('refuses a plaintext that disagrees with the columns it was bound to (dual-review O-3)', function (): void {
    // Only a holder of the envelope key can produce this — defence in depth behind the AAD.
    $row = Key::factory()->ring('http')->create(['kid' => 'forged-inside']);
    $cipher = app(StorageCipher::class);
    $aad = KeyEnvelope::associatedData($row);
    $plaintext = json_decode($cipher->decrypt(StorageCipher::KEY_ENVELOPE, (string) $row->getRawOriginal('envelope'), $aad), true);
    $plaintext['status'] = $plaintext['status'] === 'active' ? 'verify-only' : 'active';
    Key::query()->whereKey($row->id)->update(['envelope' => $cipher->encrypt(StorageCipher::KEY_ENVELOPE, Jcs::encode($plaintext), $aad)]);

    expect(fn () => app(KeyEnvelope::class)->open(Key::query()->findOrFail($row->id)))
        ->toThrow(KeyIntegrityException::class, 'failed its integrity check (status)')
        ->and(app(KeyStoreManager::class)->lookup('http', 'forged-inside'))->toEqual(new KeyLookup(null, KeyLookup::INTEGRITY));
});
