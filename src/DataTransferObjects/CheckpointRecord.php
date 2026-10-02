<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;

/**
 * A stored checkpoint (unverified).
 */
final readonly class CheckpointRecord
{
    public function __construct(
        public int $seq,
        public string $root,
        public CarbonImmutable $createdAt,
        public string $keyId,
        public int $entries = 0,
    ) {}
}
