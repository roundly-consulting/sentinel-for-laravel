<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Support\ChangedFields;
use RoundlyConsulting\Sentinel\Support\MorphedModel;

/**
 * An out-of-band change was acknowledged and re-sealed (after commit).
 */
final readonly class TamperAcknowledged implements ShouldDispatchAfterCommit
{
    /**
     * @param  list<string>|null  $changedAttributes
     */
    public function __construct(
        public string $sealableType,
        public int|string $sealableId,
        public string $seal,
        public int $version,
        public VerificationStatus $previousStatus,
        public ?array $changedAttributes,
        public string $reason,
        public ?string $actorType,
        public int|string|null $actorId,
    ) {}

    /**
     * The changed columns, without the `a:` tag prefix (`['amount']`); empty when unknown.
     *
     * @return list<string>
     */
    public function changedColumns(): array
    {
        return ChangedFields::columns($this->changedAttributes);
    }

    /**
     * The changed computed fields, without the `c:` tag prefix (`['lines']`).
     *
     * @return list<string>
     */
    public function changedComputed(): array
    {
        return ChangedFields::computed($this->changedAttributes);
    }

    /**
     * The model, loaded with verify-on-retrieve suspended (so the tampered row itself loads),
     * soft-deleted rows included; null once it is hard-deleted. The payload stays scalar.
     */
    public function model(): ?Model
    {
        return MorphedModel::find($this->sealableType, $this->sealableId, withTrashed: true);
    }
}
