<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Closure;

/**
 * Run a callback at most once per (key, scope) — `Sentinel::idempotency()->run()`. The
 * result must be JSON-encodable (it is stored, encrypted, for replays) and is returned as its
 * JSON round-trip. Calls with another fingerprint under the same key are refused. The key and
 * the scope are 1–255 bytes, `ttl` (null = `idempotency.ttl`) 60–2 592 000 seconds and `lease`
 * — how long the running call holds the key before a duplicate may take it over (null =
 * `idempotency.lock_seconds`; set it above the callback's longest run) — 1–86 400 seconds,
 * checked when the call runs (`InvalidIdempotencyKeyException`), as for the `Idempotent` job
 * middleware.
 */
final readonly class IdempotentCall
{
    public function __construct(
        public string $key,
        public string $scope,
        public Closure $callback,
        public ?string $fingerprint = null,
        public ?int $ttl = null,
        public ?int $lease = null,
    ) {}
}
