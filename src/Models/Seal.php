<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\Database\Factories\SealFactory;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Models\Concerns\StoresUtc;

/**
 * The current seal of one (sealable, seal). Lives on the sealable's connection; created only
 * through the engine (Support\Tables). Nothing here is trusted on its own: the MAC is checked
 * against a document rebuilt from the row's data, with the algorithm taken from the key.
 *
 * @property int $id
 * @property string $sealable_type
 * @property int|string $sealable_id
 * @property string $seal
 * @property int $format
 * @property string $ring
 * @property string $key_id
 * @property string $algorithm
 * @property int $version
 * @property string|null $previous_digest
 * @property string $mac
 * @property string|null $attributes_mac
 * @property list<array{0: string, 1: string}>|null $manifest
 * @property array<string, string>|null $field_tags
 * @property SealEvent $event
 * @property string|null $sealed_by_type
 * @property int|string|null $sealed_by_id
 * @property string|null $reason
 * @property CarbonImmutable $sealed_at
 * @property int|null $ledger_entry_id
 * @property CarbonImmutable|null $created_at
 * @property CarbonImmutable|null $updated_at
 */
final class Seal extends Model
{
    /** @use HasFactory<SealFactory> */
    use HasFactory;

    use StoresUtc;

    protected $table = 'sentinel_seals';

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
    public function sealedBy(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * @return BelongsTo<LedgerEntry, $this>
     */
    public function ledgerEntry(): BelongsTo
    {
        return $this->belongsTo(LedgerEntry::class);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'format' => 'integer',
            'version' => 'integer',
            'manifest' => 'array',
            'field_tags' => 'array',
            'event' => SealEvent::class,
            'sealed_at' => UtcDateTime::class,
            'created_at' => UtcDateTime::class,
            'updated_at' => UtcDateTime::class,
        ];
    }

    protected static function newFactory(): SealFactory
    {
        return SealFactory::new();
    }
}
