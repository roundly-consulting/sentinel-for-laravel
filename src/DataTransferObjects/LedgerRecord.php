<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;

/**
 * One ledger entry of a model's seal history (as stored — not verified).
 */
final readonly class LedgerRecord
{
    /**
     * @param  list<string>|null  $changed
     */
    public function __construct(
        public int $id,
        public ?SealEvent $event,
        public int $version,
        public string $ring,
        public string $keyId,
        public ?array $changed,
        public ?VerificationStatus $previousStatus,
        public ?string $actorType,
        public int|string|null $actorId,
        public ?string $reason,
        public ?CarbonImmutable $occurredAt,
        public ?int $checkpointId,
    ) {}
}
