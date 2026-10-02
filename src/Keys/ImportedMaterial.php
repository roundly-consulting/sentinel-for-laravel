<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use SensitiveParameter;

/**
 * Key material as an operator imports it (`Sentinel::keys()->ring()->import()`,
 * `sentinel:key:import`): `base64:<standard base64>` like every other key slot, or the PEM
 * block a partner sends — ECDSA keys as PKCS#8 / SPKI PEM, an Ed25519 public key as SPKI PEM
 * (unwrapped to its 32 raw bytes). PEM is structured key material, parsed and curve-checked,
 * so the `base64:`-only rule's purpose — no low-entropy passphrases — still holds.
 *
 * @internal
 */
final class ImportedMaterial
{
    /** The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): SEQUENCE, id-Ed25519, BIT STRING. */
    private const string ED25519_SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

    /**
     * Parse the material for the algorithm. Private or secret asymmetric material is refused
     * unless the import may sign; an HMAC secret is always a secret (its status decides).
     *
     * @throws InvalidKeyMaterialException never with material in the message
     */
    public static function parse(Algorithm $algorithm, #[SensitiveParameter] string $material, bool $allowPrivate): KeyMaterial
    {
        $encoded = self::encoded($algorithm, $material);

        if ($algorithm->isHmac()) {
            return KeyMaterial::fromEncoded($algorithm, $encoded);
        }

        $private = self::holdsPrivate($algorithm, MaterialCodec::decode($encoded));

        if ($private && ! $allowPrivate) {
            throw InvalidKeyMaterialException::privateNotExpected();
        }

        return $private ? KeyMaterial::fromEncoded($algorithm, $encoded) : KeyMaterial::fromEncoded($algorithm, null, $encoded);
    }

    /**
     * The `base64:` form of the material.
     */
    private static function encoded(Algorithm $algorithm, #[SensitiveParameter] string $material): string
    {
        $material = trim($material);

        if (str_starts_with($material, MaterialCodec::PREFIX)) {
            return $material;
        }

        if (! str_starts_with($material, '-----BEGIN ')) {
            throw InvalidKeyMaterialException::pemOrBase64Required();
        }

        return $algorithm === Algorithm::Ed25519 ? self::ed25519Public($material) : MaterialCodec::encode($material);
    }

    private static function ed25519Public(string $pem): string
    {
        if (preg_match('/^-----BEGIN PUBLIC KEY-----([A-Za-z0-9+\/=\s]+)-----END PUBLIC KEY-----$/D', $pem, $match) !== 1) {
            throw InvalidKeyMaterialException::wrongType(Algorithm::Ed25519, 'only an Ed25519 public key is accepted as PEM; import a secret key as base64:<64-byte secret key>');
        }

        try {
            $der = Base64::decode((string) preg_replace('/\s+/', '', $match[1]));
        } catch (InvalidEncodingException) {
            throw InvalidKeyMaterialException::malformedEncoding();
        }

        if (strlen($der) !== 44 || ! str_starts_with($der, self::ED25519_SPKI_PREFIX)) {
            throw InvalidKeyMaterialException::wrongType(Algorithm::Ed25519, 'the PEM is not an Ed25519 public key');
        }

        return MaterialCodec::encode(substr($der, strlen(self::ED25519_SPKI_PREFIX)));
    }

    private static function holdsPrivate(Algorithm $algorithm, #[SensitiveParameter] string $bytes): bool
    {
        return $algorithm === Algorithm::Ed25519 ? strlen($bytes) === 64 : str_contains($bytes, 'PRIVATE KEY');
    }
}
