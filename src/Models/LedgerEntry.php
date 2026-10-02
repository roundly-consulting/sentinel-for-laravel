<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\Database\Factories\LedgerEntryFactory;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Exceptions\LedgerIsAppendOnlyException;
use RoundlyConsulting\Sentinel\Models\Concerns\StoresUtc;

/**
 * One append-only seal event, MAC'd on its own (`sentinel.ledger/1`). Eloquent refuses to
 * update or delete it; the only mutation is the checkpoint job's assignment of
 * `checkpoint_id` through the query builder.
 *
 * @property int $id
 * @property string $sealable_type
 * @property int|string $sealable_id
 * @property string $seal
 * @property SealEvent $event
 * @property int $version
 * @property string $ring
 * @property string $key_id
 * @property string $algorithm
 * @property string|null $seal_mac
 * @property string|null $previous_digest
 * @property list<string>|null $changed
 * @property string|null $previous_status
 * @property string|null $actor_type
 * @property int|string|null $actor_id
 * @property string|null $reason
 * @property string $entry_mac
 * @property CarbonImmutable $occurred_at
 * @property int|null $checkpoint_id
 */
final class LedgerEntry extends Model
{
    /** @use HasFactory<LedgerEntryFactory> */
    use HasFactory;

    use StoresUtc;

    public $timestamps = false;

    protected $table = 'sentinel_ledger';

    protected $guarded = [];

    /**
     * @return MorphTo<Model, $this>
     */
    public function sealable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function actor(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * @return BelongsTo<Checkpoint, $this>
     */
    public function checkpoint(): BelongsTo
    {
        return $this->belongsTo(Checkpoint::class);
    }

    protected static function booted(): void
    {
        self::updating(static fn (self $entry): never => throw LedgerIsAppendOnlyException::update($entry->getTable()));
        self::deleting(static fn (self $entry): never => throw LedgerIsAppendOnlyException::delete($entry->getTable()));
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'version' => 'integer',
            'event' => SealEvent::class,
            'changed' => 'array',
            'occurred_at' => UtcDateTime::class,
        ];
    }

    protected static function newFactory(): LedgerEntryFactory
    {
        return LedgerEntryFactory::new();
    }
}
