<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Accessors;

use InvalidArgumentException;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use RoundlyConsulting\Sentinel\SentinelManager;
use SensitiveParameter;

/**
 * `Sentinel::macs()` — HMAC with secrets the caller holds (per-record webhook secrets,
 * partner secrets of any length), as opposed to `Sentinel::keys()->ring(…)->mac()`, which
 * signs with a ring's managed key. Raw bytes in and out; the wire encoding is the caller's.
 * Every call goes through the manager, so `Sentinel::fake()` sees it.
 */
final readonly class MacsAccessor
{
    /** The most secrets one `verify()` checks (the current one plus those in a grace period). */
    public const int MAX_SECRETS = 8;

    public function __construct(private SentinelManager $manager) {}

    /**
     * The raw MAC (32 / 48 / 64 bytes) of the message under the secret.
     *
     * @throws AlgorithmNotAllowedException for Ed25519 / ECDSA
     * @throws InvalidKeyMaterialException for an empty secret
     */
    public function sign(string $message, #[SensitiveParameter] string $secret, Algorithm $algorithm = Algorithm::HmacSha256): string
    {
        return $this->manager->signWithSecret($message, $secret, $algorithm);
    }

    /**
     * The index of the lowest secret the raw MAC matches, or null — constant time over every
     * secret, no early exit. A wrong-length MAC is null, never an error.
     *
     * @param  non-empty-list<string>  $secrets  at most {@see MAX_SECRETS}
     *
     * @throws AlgorithmNotAllowedException for Ed25519 / ECDSA
     * @throws InvalidKeyMaterialException for no secrets, more than 8, or an empty one
     * @throws InvalidArgumentException for a non-list or a non-string secret
     */
    public function verify(string $message, #[SensitiveParameter] string $mac, #[SensitiveParameter] array $secrets, Algorithm $algorithm = Algorithm::HmacSha256): ?int
    {
        return $this->manager->verifyWithSecrets($message, $mac, $secrets, $algorithm);
    }
}
