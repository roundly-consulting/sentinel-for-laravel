<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use RoundlyConsulting\Crypto\Hash\Hmac;
use RoundlyConsulting\Crypto\Signature\EdDSA;
use RoundlyConsulting\Crypto\Signature\Es;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use SensitiveParameter;

/**
 * Purpose-bound signing and verification through crypto-for-laravel (one of only two
 * classes allowed to touch crypto's `Hmac`/`EdDSA`/`Es` directly — arch-pinned).
 *
 * HMAC keys never MAC with the root secret: each purpose gets an HKDF subkey bound to the
 * ring, `kid` and algorithm, so a key moved to another ring or algorithm can never reproduce
 * a MAC. Signatures: Ed25519 (64 bytes) and raw ECDSA `r‖s` (64 / 96 bytes).
 *
 * @internal
 */
final readonly class Signers
{
    /**
     * @param  bool|null  $sodium  null = probe the runtime; a seam for the "no ext-sodium" path
     */
    public function __construct(private ?bool $sodium = null) {}

    /**
     * The raw MAC/signature bytes over the message.
     */
    public function sign(#[SensitiveParameter] SealingKey $key, Purpose $purpose, string $message): string
    {
        $material = $key->material();

        if (! $material->canSign()) {
            throw InvalidKeyMaterialException::publicOnly($key->ring, $key->keyId);
        }

        $algorithm = $key->algorithm();

        if ($algorithm->isHmac()) {
            return (new Hmac($algorithm->hashAlgorithm()))->sign($message, $this->subkey($key, $purpose));
        }

        return CryptoErrors::translate(
            $algorithm,
            fn (): string => $algorithm === Algorithm::Ed25519 ? $this->eddsa($key)->sign($message) : (new Es($material->ec()))->sign($message),
            'the signature could not be produced',
        );
    }

    /**
     * Constant-time MAC check / signature verification. Fails closed: a wrong-length
     * signature is simply invalid.
     */
    public function verify(#[SensitiveParameter] SealingKey $key, Purpose $purpose, string $message, string $signature): bool
    {
        $algorithm = $key->algorithm();

        if ($algorithm->isHmac()) {
            return (new Hmac($algorithm->hashAlgorithm()))->verify($message, $signature, $this->subkey($key, $purpose));
        }

        return CryptoErrors::translate(
            $algorithm,
            fn (): bool => $algorithm === Algorithm::Ed25519 ? $this->eddsa($key)->verify($message, $signature) : (new Es($key->material()->ec()))->verify($message, $signature),
        );
    }

    private function subkey(#[SensitiveParameter] SealingKey $key, Purpose $purpose): string
    {
        $algorithm = $key->algorithm();

        // RFC 9421 peers MAC with the shared secret itself; such keys live in their own ring,
        // so a partner's secret can never derive a seal or ledger subkey.
        if ($purpose === Purpose::Http) {
            return $key->material()->hmacRoot();
        }

        $info = match ($purpose) {
            Purpose::Seal => Hkdf::sealInfo($key->ring, $key->keyId, $algorithm),
            Purpose::Ledger => Hkdf::ledgerInfo($key->ring, $key->keyId, $algorithm),
        };

        return Hkdf::derive($algorithm->hashAlgorithm(), $key->material()->hmacRoot(), $algorithm->hashLength(), $info);
    }

    private function eddsa(#[SensitiveParameter] SealingKey $key): EdDSA
    {
        if (! ($this->sodium ?? function_exists('sodium_crypto_sign_detached'))) {
            throw InvalidKeyMaterialException::unsupported(Algorithm::Ed25519);
        }

        return new EdDSA($key->material()->okp());
    }
}
