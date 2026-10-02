<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Contracts;

use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Keys\SealingKey;

/**
 * The keys of one ring. Built-in drivers: `config`, `database`, `chain`; register more with
 * `Sentinel::extend('kms', fn (Container $app, string $ring, array $config): KeyStore => …)`.
 *
 * A store returns keys with their **effective** status; Sentinel still applies the
 * configured revocation list (`SENTINEL_REVOKED_KEYS`) on top, whatever the driver.
 */
interface KeyStore
{
    /**
     * The key new seals are signed with.
     *
     * @throws NoSigningKeyException
     */
    public function signingKey(): SealingKey;

    /**
     * Any key of the ring by `kid`, whatever its status; null when unknown — and when its
     * stored form fails an integrity check.
     */
    public function find(string $keyId): ?SealingKey;

    /**
     * @return list<KeyInfo>
     */
    public function all(): array;

    /**
     * Whether `generate` / `rotate` / `revoke` / `retire` write to this store (database)
     * rather than printing environment lines (config).
     */
    public function supportsWrites(): bool;
}
