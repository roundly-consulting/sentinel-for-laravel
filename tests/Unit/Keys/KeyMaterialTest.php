<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\MaterialCodec;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Keys\Signers;

function encoded(string $bytes): string
{
    return MaterialCodec::encode($bytes);
}

it('requires the base64: prefix and canonical base64', function (): void {
    expect(fn () => KeyMaterial::fromEncoded(Algorithm::HmacSha256, str_repeat('a', 44)))->toThrow(InvalidKeyMaterialException::class, 'base64:')
        ->and(fn () => KeyMaterial::fromEncoded(Algorithm::HmacSha256, 'base64:not base64!'))->toThrow(InvalidKeyMaterialException::class, 'not canonical')
        ->and(fn () => MaterialCodec::decode('base64:'))->toThrow(InvalidKeyMaterialException::class, 'not canonical')
        ->and(MaterialCodec::decode(MaterialCodec::encode("\x00\x01")))->toBe("\x00\x01");
});

it('validates HMAC roots (§10 item 31)', function (string $material, string $message): void {
    expect(fn () => KeyMaterial::fromEncoded(Algorithm::HmacSha256, $material))->toThrow(InvalidKeyMaterialException::class, $message);
})->with([
    'shorter than 32 bytes' => [fn () => encoded(random_bytes(31)), 'at least 32'],
    'longer than 1024 bytes' => [fn () => encoded(random_bytes(1025)), 'at most 1024'],
    'a single repeated byte' => [fn () => encoded(str_repeat('a', 48)), 'single repeated byte'],
    'a PEM public key' => [fn () => encoded(EcKey::generate()->publicPem()), 'public-key material cannot be an HMAC secret'],
]);

it('refuses a public half on an HMAC key and empty material', function (): void {
    expect(fn () => KeyMaterial::fromEncoded(Algorithm::HmacSha256, encoded(random_bytes(32)), encoded(random_bytes(32))))
        ->toThrow(InvalidKeyMaterialException::class, 'no public half')
        ->and(fn () => KeyMaterial::fromEncoded(Algorithm::HmacSha256, null))->toThrow(InvalidKeyMaterialException::class, 'no material');
});

it('refuses an EC key whose curve does not match the algorithm', function (): void {
    $p384 = EcKey::generate('P-384');

    expect(fn () => KeyMaterial::fromEncoded(Algorithm::EcdsaP256Sha256, encoded($p384->privatePem())))
        ->toThrow(InvalidKeyMaterialException::class, 'curve does not match')
        ->and(fn () => KeyMaterial::fromEncoded(Algorithm::EcdsaP384Sha384, null, encoded(EcKey::generate('P-521')->publicPem())))
        ->toThrow(InvalidKeyMaterialException::class, 'curve does not match');
});

it('refuses non-EC and unreadable PEM under ECDSA', function (string $material): void {
    expect(fn () => KeyMaterial::fromEncoded(Algorithm::EcdsaP256Sha256, $material))->toThrow(InvalidKeyMaterialException::class, 'PEM text');
})->with([
    'random bytes' => [fn () => encoded(random_bytes(64))],
    'an RSA key' => [function (): string {
        $rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        openssl_pkey_export($rsa, $pem);

        return encoded($pem);
    }],
]);

it('refuses EC private and public halves that do not belong together', function (): void {
    expect(fn () => KeyMaterial::fromEncoded(Algorithm::EcdsaP256Sha256, encoded(EcKey::generate()->privatePem()), encoded(EcKey::generate()->publicPem())))
        ->toThrow(InvalidKeyMaterialException::class, 'does not belong');
});

it('refuses Ed25519 material of the wrong shape, including a 64-byte HMAC secret', function (?string $secret, ?string $public, string $message): void {
    expect(fn () => KeyMaterial::fromEncoded(Algorithm::Ed25519, $secret, $public))->toThrow(InvalidKeyMaterialException::class, $message);
})->with([
    '32-byte HMAC secret as the secret key' => [fn () => encoded(random_bytes(32)), null, '64-byte libsodium'],
    '64 random bytes (not a keypair)' => [fn () => encoded(random_bytes(64)), null, 'does not embed its own public key'],
    '31-byte public key' => [null, fn () => encoded(random_bytes(31)), '32 bytes'],
    'mismatched public key' => [
        fn () => encoded(sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair())),
        fn () => encoded(sodium_crypto_sign_publickey(sodium_crypto_sign_keypair())),
        'does not belong',
    ],
]);

it('generates, exports and reloads every algorithm', function (Algorithm $algorithm): void {
    $generated = KeyMaterial::generate($algorithm);

    expect($generated->algorithm)->toBe($algorithm)->and($generated->canSign())->toBeTrue();

    $reloaded = KeyMaterial::fromEncoded($algorithm, $generated->encodedPrivate(), $generated->encodedPublic());

    expect($reloaded->encodedPrivate())->toBe($generated->encodedPrivate())
        ->and($reloaded->encodedPublic())->toBe($generated->encodedPublic());

    if ($algorithm->isAsymmetric()) {
        $public = KeyMaterial::fromEncoded($algorithm, null, $generated->encodedPublic());

        expect($public->canSign())->toBeFalse()
            ->and($public->encodedPrivate())->toBeNull()
            ->and($public->encodedPublic())->toBe($generated->encodedPublic());
    } else {
        expect(strlen(MaterialCodec::decode((string) $generated->encodedPrivate())))->toBe($algorithm->hashLength())
            ->and($generated->encodedPublic())->toBeNull();
    }
})->with(Algorithm::cases());

it('exposes only the accessor that matches its algorithm', function (): void {
    $hmac = KeyMaterial::generate(Algorithm::HmacSha256);
    $ed = KeyMaterial::generate(Algorithm::Ed25519);
    $ec = KeyMaterial::generate(Algorithm::EcdsaP256Sha256);

    expect(strlen($hmac->hmacRoot()))->toBe(32)
        ->and($ed->okp()->secretKey)->not->toBeNull()
        ->and($ec->ec()->isPrivate)->toBeTrue()
        ->and(fn () => $hmac->okp())->toThrow(LogicException::class)
        ->and(fn () => $hmac->ec())->toThrow(LogicException::class)
        ->and(fn () => $ed->hmacRoot())->toThrow(LogicException::class);
});

it('verifies ECDSA signatures through the private key it signs with', function (Algorithm $algorithm): void {
    // Pins crypto-for-laravel a778e2e: Es::verify() through a private EcKey (it used to return
    // false, which Sentinel worked around by deriving the public key at load time).
    $key = new SealingKey('default', 'ec', KeyMaterial::generate($algorithm));
    $signers = new Signers;
    $signature = $signers->sign($key, Purpose::Seal, 'message');

    expect($key->material()->ec()->isPrivate)->toBeTrue()
        ->and($signers->verify($key, Purpose::Seal, 'message', $signature))->toBeTrue()
        ->and($signers->verify($key, Purpose::Seal, 'tampered', $signature))->toBeFalse();
})->with([Algorithm::EcdsaP256Sha256, Algorithm::EcdsaP384Sha384]);

it('never reveals material through var_dump, print_r or serialize', function (Algorithm $algorithm): void {
    $material = KeyMaterial::generate($algorithm);
    $secret = (string) $material->encodedPrivate();

    ob_start();
    var_dump($material);
    $dump = (string) ob_get_clean().print_r($material, true);

    expect($dump)->not->toContain(substr($secret, 7, 24))->toContain('[redacted]')
        ->and(fn () => serialize($material))->toThrow(LogicException::class)
        ->and(fn () => unserialize('O:'.strlen(KeyMaterial::class).':"'.KeyMaterial::class.'":0:{}'))->toThrow(LogicException::class);
})->with([Algorithm::HmacSha256, Algorithm::Ed25519]);
