<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use RoundlyConsulting\Sentinel\Enums\IdempotencyRejection;

/**
 * An idempotent request was refused (synchronously): a missing or invalid key, a key reused
 * with another payload, one still in flight, or a response that cannot be replayed.
 */
final readonly class IdempotencyRejected
{
    public function __construct(
        public string $method,
        public string $route,
        public int $status,
        public IdempotencyRejection $reason,
    ) {}
}
