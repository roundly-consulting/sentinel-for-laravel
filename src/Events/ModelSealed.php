<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Support\MorphedModel;

/**
 * A seal was written (after commit). Scalars only — never values or key material.
 */
final readonly class ModelSealed implements ShouldDispatchAfterCommit
{
    public function __construct(
        public string $sealableType,
        public int|string $sealableId,
        public string $seal,
        public int $version,
        public string $keyId,
        public SealEvent $event,
        public ?string $actorType = null,
        public int|string|null $actorId = null,
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
