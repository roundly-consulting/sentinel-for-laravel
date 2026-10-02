<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Support\MorphedModel;

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

    /**
     * The model, loaded with verify-on-retrieve suspended (so the tampered row itself loads),
     * soft-deleted rows included; null once it is hard-deleted. The payload stays scalar.
     */
    public function model(): ?Model
    {
        return MorphedModel::find($this->sealableType, $this->sealableId, withTrashed: true);
    }
}
