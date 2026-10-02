<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Enums\Algorithm;

/**
 * The latest checkpoint as published to an external anchor (`sentinel.anchor/1`). It carries
 * the checkpoint's own MAC, so an edited anchor is detectable.
 */
final readonly class AnchorPayload
{
    public function __construct(
        public string $connection,
        public int $seq,
        public string $root,
        public CarbonImmutable $at,
        public string $ring,
        public string $keyId,
        public Algorithm $algorithm,
        public string $mac,
    ) {}
}
