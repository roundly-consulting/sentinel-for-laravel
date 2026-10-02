<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;

/**
 * The value of an idempotent call — fresh, or replayed from the first call. `value` is the JSON
 * round-trip of the callback's result on both paths (objects become associative arrays,
 * `JsonSerializable` / `Arrayable` their serialized form), so code reading it works the same
 * on the first run and on every retry.
 */
final readonly class IdempotentResult
{
    public function __construct(
        public mixed $value,
        public bool $replayed,
        public CarbonImmutable $firstSeenAt,
    ) {}
}
