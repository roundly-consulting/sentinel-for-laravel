<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Enums\SealEvent;

/**
 * The stored seal row of a model, as it is (nothing here is verified — use `verify()`).
 */
final readonly class SealRecord
{
    /**
     * @param  list<list<string>>  $manifest  `[[name, declaredTag], …]` as stored
     */
    public function __construct(
        public string $sealableType,
        public int|string $sealableId,
        public string $seal,
        public int $version,
        public string $ring,
        public string $keyId,
        public string $algorithm,
        public array $manifest,
        public ?CarbonImmutable $sealedAt,
        public ?SealEvent $event,
        public ?string $reason,
        public ?string $sealedByType,
        public int|string|null $sealedById,
    ) {}
}
