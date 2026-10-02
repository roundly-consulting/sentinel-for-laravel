<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Contracts;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;

/**
 * Where nonce digests live. Built in: `database` (default) and `cache` (a lock-capable store).
 * Consuming and remembering must be atomic: of many concurrent calls for one nonce, exactly one
 * succeeds.
 */
interface NonceStore
{
    public function issue(string $purpose, string $digest, CarbonImmutable $expiresAt, ?Model $subject): void;

    /**
     * Use an issued nonce once: unexpired, unused, same purpose and subject — else false.
     */
    public function consume(string $purpose, string $digest, CarbonImmutable $now, ?Model $subject): bool;

    /**
     * Record a nonce seen from a client until `until`; false when it was seen already (a
     * replay). An expired record no longer counts.
     */
    public function remember(string $purpose, string $digest, CarbonImmutable $until, CarbonImmutable $now): bool;

    public function prune(CarbonImmutable $now): int;
}
