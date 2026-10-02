<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Signature\Algorithm as CryptoAlgorithm;
use RoundlyConsulting\Enums\Helpers;

/**
 * The seal / HTTP-signature algorithms. Values are the RFC 9421 registry names where one
 * exists, and are frozen: hosts persist them (seal rows, key rows, ledger entries).
 *
 * An algorithm is always taken from the resolved key, never from stored or received data
 * (RFC 8725 §3.1 applied to seals).
 */
enum Algorithm: string
{
    use Helpers;

    case HmacSha256 = 'hmac-sha256';
    case HmacSha384 = 'hmac-sha384';
    case HmacSha512 = 'hmac-sha512';
    case Ed25519 = 'ed25519';
    case EcdsaP256Sha256 = 'ecdsa-p256-sha256';
    case EcdsaP384Sha384 = 'ecdsa-p384-sha384';

    public function isHmac(): bool
    {
        return match ($this) {
            self::HmacSha256, self::HmacSha384, self::HmacSha512 => true,
            default => false,
        };
    }

    public function isAsymmetric(): bool
    {
        return ! $this->isHmac();
    }

    /**
     * The hash function name (`sha256`, `sha384`, `sha512`). Ed25519 hashes with SHA-512
     * internally.
     */
    public function hashName(): string
    {
        return $this->hashAlgorithm()->value;
    }

    /**
     * The hash output length in bytes — the HKDF subkey length for HMAC seals.
     */
    public function hashLength(): int
    {
        return match ($this->hashAlgorithm()) {
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
            default => 32,
        };
    }

    public function hashAlgorithm(): HashAlgorithm
    {
        return match ($this) {
            self::HmacSha256, self::EcdsaP256Sha256 => HashAlgorithm::Sha256,
            self::HmacSha384, self::EcdsaP384Sha384 => HashAlgorithm::Sha384,
            self::HmacSha512, self::Ed25519 => HashAlgorithm::Sha512,
        };
    }

    /**
     * The crypto-for-laravel signature algorithm the key material is pinned to.
     */
    public function cryptoAlgorithm(): CryptoAlgorithm
    {
        return match ($this) {
            self::HmacSha256 => CryptoAlgorithm::HS256,
            self::HmacSha384 => CryptoAlgorithm::HS384,
            self::HmacSha512 => CryptoAlgorithm::HS512,
            self::Ed25519 => CryptoAlgorithm::EdDSA,
            self::EcdsaP256Sha256 => CryptoAlgorithm::ES256,
            self::EcdsaP384Sha384 => CryptoAlgorithm::ES384,
        };
    }

    /**
     * Whether RFC 9421 registers the algorithm (only these may sign HTTP messages).
     */
    public function isHttpRegistered(): bool
    {
        return match ($this) {
            self::HmacSha384, self::HmacSha512 => false,
            default => true,
        };
    }
}
