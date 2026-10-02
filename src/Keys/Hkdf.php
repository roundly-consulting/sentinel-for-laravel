<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use SensitiveParameter;
use ValueError;

/**
 * HKDF (RFC 5869) — the one primitive crypto-for-laravel lacks, isolated here: this is the
 * only caller of `hash_hkdf` in the package (arch-pinned).
 *
 * Per-purpose subkeys keep one root secret from ever MACing two kinds of document under the
 * same key. The salt is a fixed, non-secret constant (RFC 5869 §3.1); the info strings are
 * NUL-separated, and no identifier can contain NUL.
 *
 * @internal
 */
final class Hkdf
{
    public const string SALT = 'sentinel.hkdf/1';

    /**
     * A subkey under the fixed Sentinel salt.
     */
    public static function derive(HashAlgorithm $hash, #[SensitiveParameter] string $ikm, int $length, string $info): string
    {
        return self::raw($hash, $ikm, $length, $info, self::SALT);
    }

    /**
     * Plain RFC 5869 HKDF (extract + expand) with an explicit salt.
     */
    public static function raw(HashAlgorithm $hash, #[SensitiveParameter] string $ikm, int $length, string $info, string $salt): string
    {
        if ($ikm === '') {
            throw InvalidKeyMaterialException::wrongType(Algorithm::HmacSha256, 'the input keying material is empty');
        }

        if ($length < 1) {
            throw InvalidKeyMaterialException::wrongType(Algorithm::HmacSha256, 'the requested subkey length is invalid');
        }

        try {
            return hash_hkdf($hash->value, $ikm, $length, $info, $salt);
        } catch (ValueError $error) {
            throw InvalidKeyMaterialException::wrongType(Algorithm::HmacSha256, 'the requested subkey length is invalid', $error);
        }
    }

    public static function sealInfo(string $ring, string $keyId, Algorithm $algorithm): string
    {
        return "sentinel/1/seal\0{$ring}\0{$keyId}\0{$algorithm->value}";
    }

    public static function ledgerInfo(string $ring, string $keyId, Algorithm $algorithm): string
    {
        return "sentinel/1/ledger\0{$ring}\0{$keyId}\0{$algorithm->value}";
    }

    public static function fieldInfo(string $ring, string $keyId): string
    {
        return "sentinel/1/field\0{$ring}\0{$keyId}";
    }
}
