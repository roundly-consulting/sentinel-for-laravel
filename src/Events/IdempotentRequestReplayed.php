<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

/**
 * A request was answered with the stored response of an earlier one (synchronously).
 */
final readonly class IdempotentRequestReplayed
{
    public function __construct(
        public string $method,
        public string $route,
        public int $status,
    ) {}
}
