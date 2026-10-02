<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\MaterialCodec;
use RoundlyConsulting\Sentinel\Keys\RingConfig;
use RoundlyConsulting\Sentinel\Keys\Stores\ConfigKeyStore;
use RoundlyConsulting\Sentinel\Tests\TestCase;

function configStore(array $overrides = [], array $revoked = []): ConfigKeyStore
{
    $values = [
        'name' => 'default', 'driver' => 'config', 'algorithms' => Algorithm::cases(), 'keyId' => 'current',
        'algorithm' => Algorithm::HmacSha256, 'key' => TestCase::ROOT_KEY, 'publicKey' => null, 'previous' => '', 'drivers' => ['config'],
        ...$overrides,
    ];

    return new ConfigKeyStore(new RingConfig(...$values), $revoked, CarbonImmutable::now());
}

it('signs with the current key and lists it', function (): void {
    $store = configStore();

    expect($store->signingKey()->keyId)->toBe('current')
        ->and($store->signingKey()->status)->toBe(KeyStatus::Active)
        ->and($store->signingKey()->driver)->toBe('config')
        ->and($store->find('current')?->algorithm())->toBe(Algorithm::HmacSha256)
        ->and($store->find('other'))->toBeNull()
        ->and($store->all())->toHaveCount(1)
        ->and($store->supportsWrites())->toBeFalse();
});

it('loads every kind of verify-only previous key', function (): void {
    $ed = KeyMaterial::generate(Algorithm::Ed25519);
    $ec = EcKey::generate('P-384');
    $previous = implode(',', [
        'old-hmac|hmac-sha512|'.MaterialCodec::encode(random_bytes(64)),
        'old-ed-public|ed25519|'.$ed->encodedPublic(),
        'old-ed-secret|ed25519|'.$ed->encodedPrivate(),
        'old-ec-public|ecdsa-p384-sha384|'.MaterialCodec::encode($ec->publicPem()),
        'old-ec-private|ecdsa-p384-sha384|'.MaterialCodec::encode($ec->privatePem()),
    ]);

    $store = configStore(['previous' => " {$previous} "]);

    foreach (['old-hmac', 'old-ed-public', 'old-ed-secret', 'old-ec-public', 'old-ec-private'] as $keyId) {
        expect($store->find($keyId)?->status)->toBe(KeyStatus::VerifyOnly)
            ->and($store->find($keyId)?->canSign())->toBeFalse();
    }

    expect($store->find('old-ed-secret')?->material()->canSign())->toBeTrue()
        ->and($store->find('old-ec-public')?->material()->canSign())->toBeFalse()
        ->and($store->all())->toHaveCount(6);
});

it('makes a public-only current key verify-only (a verify-only node)', function (): void {
    $material = KeyMaterial::generate(Algorithm::Ed25519);
    $store = configStore(['algorithm' => Algorithm::Ed25519, 'key' => null, 'publicKey' => $material->encodedPublic()]);

    expect($store->find('current')?->status)->toBe(KeyStatus::VerifyOnly)
        ->and(fn () => $store->signingKey())->toThrow(NoSigningKeyException::class);
});

it('applies the revocation list to current and previous keys', function (): void {
    $store = configStore(['previous' => 'old|hmac-sha256|'.MaterialCodec::encode(random_bytes(32))], ['default:current', 'default:old']);

    expect($store->find('current')?->status)->toBe(KeyStatus::Revoked)
        ->and($store->find('old')?->status)->toBe(KeyStatus::Revoked)
        ->and(fn () => $store->signingKey())->toThrow(NoSigningKeyException::class);
});

it('has no signing key when nothing is configured', function (): void {
    $store = configStore(['keyId' => null, 'key' => null]);

    expect($store->all())->toBe([])
        ->and(fn () => $store->signingKey())->toThrow(NoSigningKeyException::class, 'sentinel:key:generate --ring=default');
});

it('refuses invalid configured keys without echoing material', function (array $overrides, string $message): void {
    $store = configStore($overrides);

    try {
        $store->all();
        $this->fail('expected a configuration error');
    } catch (InvalidSentinelConfigurationException $exception) {
        expect($exception->getMessage())->toContain($message)->not->toContain('AQIDBAUG');
    }
})->with([
    'key without key id' => [['keyId' => null], 'keys.rings.default.key_id] is required'],
    'malformed previous entry' => [['previous' => 'no-pipes-here'], 'previous] entry #1'],
    'unknown previous algorithm' => [['previous' => 'old|none|'.TestCase::ROOT_KEY], 'previous] entry #1'],
    'invalid previous kid' => [['previous' => '-bad|hmac-sha256|'.TestCase::ROOT_KEY], 'previous] entry #1'],
    'weak previous material' => [['previous' => 'ok|hmac-sha256|base64:'.base64_encode('short')], 'previous] entry #1'],
    'second entry broken' => [['previous' => 'ok|hmac-sha256|'.TestCase::ROOT_KEY.',broken'], 'previous] entry #2'],
    'duplicate key id' => [['previous' => 'current|hmac-sha256|'.TestCase::ROOT_KEY], 'repeats the key id [current]'],
]);
