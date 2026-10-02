<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\SealEvent;

/**
 * A seal that was just written.
 */
final readonly class SealResult
{
    public function __construct(
        public string $sealableType,
        public int|string $sealableId,
        public string $seal,
        public int $version,
        public string $ring,
        public string $keyId,
        public Algorithm $algorithm,
        public CarbonImmutable $sealedAt,
        public SealEvent $event,
        public ?int $ledgerEntryId,
    ) {}
}
