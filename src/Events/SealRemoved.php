<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;

/**
 * A seal row was removed and a tombstone written: the model was hard-deleted (`deleted`) or
 * deliberately unsealed (`unsealed`). After commit.
 */
final readonly class SealRemoved implements ShouldDispatchAfterCommit
{
    public function __construct(
        public string $sealableType,
        public int|string $sealableId,
        public string $seal,
        public SealEvent $event,
        public ?VerificationStatus $previousStatus,
    ) {}
}
