<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use LogicException;
use RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Signature\EdDSA;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use SensitiveParameter;

/**
 * Validated key material, pinned to exactly one algorithm (plan §4.4.4).
 *
 *  - HMAC: a root secret of 32..1024 random bytes (crypto `HmacSecret`: never empty, never
 *    PEM/DER key material, never a single repeated byte). Subkeys are HKDF-derived per use.
 *  - Ed25519: the 64-byte libsodium secret key and/or the 32-byte public key; a secret key
 *    must embed its own public key (proven by a sign/verify probe), so an arbitrary 64-byte
 *    HMAC secret cannot load as `ed25519`.
 *  - ECDSA: PKCS#8 / SPKI PEM whose curve matches the algorithm (P-256 ↔ ecdsa-p256-sha256).
 *
 * The material never leaves through `var_dump`, `serialize()` or `__toString`. Part of the
 * custom key-store extension surface (a driver builds `SealingKey`s from it).
 */
final readonly class KeyMaterial
{
    private const int HMAC_MIN_BYTES = 32;

    private const int HMAC_MAX_BYTES = 1024;

    private const string ED25519_PROBE = 'sentinel.key-probe/1';

    private function __construct(
        public Algorithm $algorithm,
        #[SensitiveParameter] private ?HmacSecret $secret = null,
        private ?OkpKey $okp = null,
        private ?EcKey $ec = null,
        private ?EcKey $ecPublic = null,
    ) {}

    /**
     * Load `base64:`-encoded material: the private/secret half, the public half, or both
     * (which must then belong together).
     */
    public static function fromEncoded(Algorithm $algorithm, #[SensitiveParameter] ?string $private, ?string $public = null): self
    {
        if ($private === null && $public === null) {
            throw InvalidKeyMaterialException::wrongType($algorithm, 'no material was given');
        }

        return self::fromBytes(
            $algorithm,
            $private === null ? null : MaterialCodec::decode($private),
            $public === null ? null : MaterialCodec::decode($public),
        );
    }

    /**
     * Fresh material from the CSPRNG (HMAC roots are as long as the hash output).
     */
    public static function generate(Algorithm $algorithm): self
    {
        try {
            return match ($algorithm) {
                Algorithm::HmacSha256, Algorithm::HmacSha384, Algorithm::HmacSha512 => new self($algorithm, secret: HmacSecret::generate($algorithm->hashLength())),
                Algorithm::Ed25519 => new self($algorithm, okp: OkpKey::generate()),
                Algorithm::EcdsaP256Sha256, Algorithm::EcdsaP384Sha384 => self::withPublic(
                    $algorithm,
                    EcKey::generate($algorithm === Algorithm::EcdsaP256Sha256 ? 'P-256' : 'P-384'),
                ),
            };
        } catch (UnsupportedAlgorithmException $exception) {
            throw InvalidKeyMaterialException::unsupported($algorithm, $exception);
        }
    }

    public function canSign(): bool
    {
        return match (true) {
            $this->secret !== null => true,
            $this->okp !== null => $this->okp->secretKey !== null,
            $this->ec !== null => $this->ec->isPrivate,
            default => false,
        };
    }

    /**
     * The HMAC root secret (input keying material for HKDF).
     */
    public function hmacRoot(): string
    {
        if ($this->secret === null) {
            throw new LogicException("A {$this->algorithm->value} key has no HMAC secret.");
        }

        return $this->secret->value;
    }

    public function okp(): OkpKey
    {
        return $this->okp ?? throw new LogicException("A {$this->algorithm->value} key is not an Ed25519 key.");
    }

    /**
     * The EC key to sign with (private when held, else public).
     */
    public function ec(): EcKey
    {
        return $this->ec ?? throw new LogicException("A {$this->algorithm->value} key is not an EC key.");
    }

    /**
     * The public EC key to verify with. OpenSSL cannot verify through a private-key object
     * (crypto's `Es::verify()` returns false for one), so the public half is always derived
     * at load time.
     */
    public function ecPublic(): EcKey
    {
        return $this->ecPublic ?? throw new LogicException("A {$this->algorithm->value} key is not an EC key.");
    }

    /**
     * The `base64:` form of the private/secret half, or null when only public material is
     * held. Secret — only ever printed by `sentinel:key:generate` for a config destination.
     */
    public function encodedPrivate(): ?string
    {
        return match (true) {
            $this->secret !== null => MaterialCodec::encode($this->secret->value),
            $this->okp !== null => $this->okp->secretKey === null ? null : MaterialCodec::encode($this->okp->secretKey),
            $this->ec !== null => $this->ec->isPrivate ? MaterialCodec::encode($this->ec->privatePem()) : null,
            default => null,
        };
    }

    /**
     * The `base64:` form of the public half (null for HMAC, which has none).
     */
    public function encodedPublic(): ?string
    {
        return match (true) {
            $this->okp !== null => MaterialCodec::encode($this->okp->publicKey),
            $this->ec !== null => MaterialCodec::encode($this->ec->publicPem()),
            default => null,
        };
    }

    /**
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['algorithm' => $this->algorithm->value, 'material' => '[redacted]'];
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new LogicException('Key material cannot be serialized.');
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException('Key material cannot be unserialized.');
    }

    private static function fromBytes(Algorithm $algorithm, #[SensitiveParameter] ?string $private, ?string $public): self
    {
        try {
            return match ($algorithm) {
                Algorithm::HmacSha256, Algorithm::HmacSha384, Algorithm::HmacSha512 => self::hmac($algorithm, $private, $public),
                Algorithm::Ed25519 => self::ed25519($private, $public),
                Algorithm::EcdsaP256Sha256, Algorithm::EcdsaP384Sha384 => self::ecdsa($algorithm, $private, $public),
            };
        } catch (UnsupportedAlgorithmException $exception) {
            throw InvalidKeyMaterialException::unsupported($algorithm, $exception);
        }
    }

    private static function hmac(Algorithm $algorithm, #[SensitiveParameter] ?string $private, ?string $public): self
    {
        if ($private === null || $public !== null) {
            throw InvalidKeyMaterialException::wrongType($algorithm, 'an HMAC key is a single secret with no public half');
        }

        if (strlen($private) < self::HMAC_MIN_BYTES) {
            throw InvalidKeyMaterialException::tooShort($algorithm, self::HMAC_MIN_BYTES);
        }

        if (strlen($private) > self::HMAC_MAX_BYTES) {
            throw InvalidKeyMaterialException::tooLong($algorithm, self::HMAC_MAX_BYTES);
        }

        try {
            return new self($algorithm, secret: HmacSecret::fromString($private));
        } catch (WeakKeyException $exception) {
            if (strlen((string) count_chars($private, 3)) === 1) {
                throw InvalidKeyMaterialException::weakSecret($algorithm);
            }

            // The only other refusal past the length guard: PEM/DER key material.
            throw InvalidKeyMaterialException::wrongType($algorithm, 'public-key material cannot be an HMAC secret', $exception);
        }
    }

    private static function ed25519(#[SensitiveParameter] ?string $private, ?string $public): self
    {
        $algorithm = Algorithm::Ed25519;

        try {
            $key = $private !== null ? OkpKey::fromSecretKey($private) : OkpKey::ed25519((string) $public);
        } catch (UnsupportedAlgorithmException $exception) {
            throw $exception;
        } catch (CryptoException $exception) {
            throw InvalidKeyMaterialException::wrongType($algorithm, $private !== null
                ? 'the secret key must be the 64-byte libsodium secret key'
                : 'the public key must be 32 bytes', $exception);
        }

        if ($private !== null) {
            $probe = new EdDSA($key);

            if (! $probe->verify(self::ED25519_PROBE, $probe->sign(self::ED25519_PROBE))) {
                throw InvalidKeyMaterialException::wrongType($algorithm, 'the secret key does not embed its own public key');
            }

            if ($public !== null && $public !== $key->publicKey) {
                throw InvalidKeyMaterialException::wrongType($algorithm, 'the public key does not belong to the secret key');
            }
        }

        return new self($algorithm, okp: $key);
    }

    private static function ecdsa(Algorithm $algorithm, #[SensitiveParameter] ?string $private, ?string $public): self
    {
        try {
            $key = $private !== null ? EcKey::private($private) : EcKey::public((string) $public);
            $publicKey = $private !== null && $public !== null ? EcKey::public($public) : null;
        } catch (CryptoException $exception) {
            throw InvalidKeyMaterialException::wrongType($algorithm, 'expected PEM text of a P-256 or P-384 EC key', $exception);
        }

        if ($key->algorithm() !== $algorithm->cryptoAlgorithm()) {
            throw InvalidKeyMaterialException::curveMismatch($algorithm);
        }

        if ($publicKey !== null && $publicKey->publicPem() !== $key->publicPem()) {
            throw InvalidKeyMaterialException::wrongType($algorithm, 'the public key does not belong to the private key');
        }

        return self::withPublic($algorithm, $key);
    }

    private static function withPublic(Algorithm $algorithm, #[SensitiveParameter] EcKey $key): self
    {
        return new self($algorithm, ec: $key, ecPublic: $key->isPrivate ? EcKey::public($key->publicPem()) : $key);
    }
}
