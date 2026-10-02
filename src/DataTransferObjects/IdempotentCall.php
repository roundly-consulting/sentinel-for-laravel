<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Closure;

/**
 * Run a callback at most once per (key, scope) — `Sentinel::idempotency()->run()`. The
 * result must be JSON-encodable (it is stored, encrypted, for replays) and is returned as its
 * JSON round-trip. Calls with another fingerprint under the same key are refused.
 */
final readonly class IdempotentCall
{
    public function __construct(
        public string $key,
        public string $scope,
        public Closure $callback,
        public ?string $fingerprint = null,
        public ?int $ttl = null,
    ) {}
}
