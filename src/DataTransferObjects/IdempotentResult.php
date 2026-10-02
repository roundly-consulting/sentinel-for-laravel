<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;

/**
 * The value of an idempotent call — fresh, or replayed from the first call.
 */
final readonly class IdempotentResult
{
    public function __construct(
        public mixed $value,
        public bool $replayed,
        public CarbonImmutable $firstSeenAt,
    ) {}
}
