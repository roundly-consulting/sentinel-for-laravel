<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Keys\Signers;

function sealingKey(Algorithm $algorithm, string $ring = 'default', string $kid = 'k1', ?KeyMaterial $material = null): SealingKey
{
    return new SealingKey($ring, $kid, $material ?? KeyMaterial::generate($algorithm));
}

it('signs and verifies with every algorithm, failing closed on any change', function (Algorithm $algorithm, int $length): void {
    $signers = new Signers;
    $key = sealingKey($algorithm);

    $signature = $signers->sign($key, Purpose::Seal, 'document');

    expect(strlen($signature))->toBe($length)
        ->and($signers->verify($key, Purpose::Seal, 'document', $signature))->toBeTrue()
        ->and($signers->verify($key, Purpose::Seal, 'documenT', $signature))->toBeFalse()
        ->and($signers->verify($key, Purpose::Seal, 'document', substr($signature, 1)))->toBeFalse()
        ->and($signers->verify($key, Purpose::Seal, 'document', ''))->toBeFalse();
})->with([
    [Algorithm::HmacSha256, 32],
    [Algorithm::HmacSha384, 48],
    [Algorithm::HmacSha512, 64],
    [Algorithm::Ed25519, 64],
    [Algorithm::EcdsaP256Sha256, 64],
    [Algorithm::EcdsaP384Sha384, 96],
]);

it('verifies with public-only material and refuses to sign with it', function (Algorithm $algorithm): void {
    $signers = new Signers;
    $material = KeyMaterial::generate($algorithm);
    $public = sealingKey($algorithm, material: KeyMaterial::fromEncoded($algorithm, null, $material->encodedPublic()));

    $signature = $signers->sign(sealingKey($algorithm, material: $material), Purpose::Seal, 'm');

    expect($signers->verify($public, Purpose::Seal, 'm', $signature))->toBeTrue()
        ->and(fn () => $signers->sign($public, Purpose::Seal, 'm'))->toThrow(InvalidKeyMaterialException::class, 'only public material');
})->with([Algorithm::Ed25519, Algorithm::EcdsaP256Sha256, Algorithm::EcdsaP384Sha384]);

it('derives a distinct HMAC subkey per purpose, ring, kid and algorithm', function (): void {
    $signers = new Signers;
    $root = KeyMaterial::generate(Algorithm::HmacSha256)->encodedPrivate();

    $macs = [
        $signers->sign(sealingKey(Algorithm::HmacSha256, 'default', 'k1', KeyMaterial::fromEncoded(Algorithm::HmacSha256, $root)), Purpose::Seal, 'm'),
        $signers->sign(sealingKey(Algorithm::HmacSha256, 'default', 'k1', KeyMaterial::fromEncoded(Algorithm::HmacSha256, $root)), Purpose::Ledger, 'm'),
        $signers->sign(sealingKey(Algorithm::HmacSha256, 'http', 'k1', KeyMaterial::fromEncoded(Algorithm::HmacSha256, $root)), Purpose::Seal, 'm'),
        $signers->sign(sealingKey(Algorithm::HmacSha256, 'default', 'k2', KeyMaterial::fromEncoded(Algorithm::HmacSha256, $root)), Purpose::Seal, 'm'),
        substr($signers->sign(sealingKey(Algorithm::HmacSha512, 'default', 'k1', KeyMaterial::fromEncoded(Algorithm::HmacSha512, $root)), Purpose::Seal, 'm'), 0, 32),
    ];

    expect(array_unique($macs))->toHaveCount(5);
});

it('matches the raw HKDF + HMAC construction (independent oracle)', function (): void {
    $material = KeyMaterial::generate(Algorithm::HmacSha384);
    $key = sealingKey(Algorithm::HmacSha384, 'default', 'kid-x', $material);
    $subkey = hash_hkdf('sha384', $material->hmacRoot(), 48, "sentinel/1/seal\0default\0kid-x\0hmac-sha384", 'sentinel.hkdf/1');

    expect((new Signers)->sign($key, Purpose::Seal, 'doc'))->toBe(hash_hmac('sha384', 'doc', $subkey, true));
});

it('matches libsodium for Ed25519 (independent oracle)', function (): void {
    $material = KeyMaterial::generate(Algorithm::Ed25519);
    $key = sealingKey(Algorithm::Ed25519, material: $material);

    expect((new Signers)->sign($key, Purpose::Ledger, 'doc'))->toBe(sodium_crypto_sign_detached('doc', (string) $material->okp()->secretKey));
});

it('fails Ed25519 loudly without ext-sodium (simulated through the Signers seam)', function (): void {
    $signers = new Signers(sodium: false);
    $key = sealingKey(Algorithm::Ed25519);

    expect(fn () => $signers->sign($key, Purpose::Seal, 'm'))->toThrow(InvalidKeyMaterialException::class, 'ext-sodium')
        ->and(fn () => $signers->verify($key, Purpose::Seal, 'm', str_repeat("\0", 64)))->toThrow(InvalidKeyMaterialException::class, 'ext-sodium');
});

it('reports a sealing key status and keeps its material out of dumps and serialization', function (): void {
    $key = sealingKey(Algorithm::HmacSha256);

    expect($key->algorithm())->toBe(Algorithm::HmacSha256)
        ->and($key->canSign())->toBeTrue()
        ->and($key->canVerify())->toBeTrue()
        ->and($key->withStatus(KeyStatus::VerifyOnly)->canSign())->toBeFalse()
        ->and($key->withStatus(KeyStatus::VerifyOnly)->canVerify())->toBeTrue()
        ->and($key->withStatus(KeyStatus::Revoked)->canVerify())->toBeFalse()
        ->and($key->withStatus(KeyStatus::Retired)->keyId)->toBe('k1')
        ->and(print_r($key, true))->toContain('[redacted]')->not->toContain(substr((string) $key->material()->encodedPrivate(), 7, 20))
        ->and(fn () => serialize($key))->toThrow(LogicException::class)
        ->and(fn () => unserialize('O:'.strlen(SealingKey::class).':"'.SealingKey::class.'":0:{}'))->toThrow(LogicException::class);
});
