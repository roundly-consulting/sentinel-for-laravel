<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

/**
 * How many expired records were (or, on a dry run, would be) removed.
 */
final readonly class PruneResult
{
    public function __construct(
        public int $idempotencyKeys,
        public int $nonces,
    ) {}
}
