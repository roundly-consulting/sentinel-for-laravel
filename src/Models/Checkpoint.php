<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\Database\Factories\CheckpointFactory;
use RoundlyConsulting\Sentinel\Exceptions\LedgerIsAppendOnlyException;
use RoundlyConsulting\Sentinel\Models\Concerns\StoresUtc;

/**
 * A keyed, chained digest over a batch of ledger entries (`sentinel.checkpoint/1`).
 * Append-only. Written by the checkpoint job.
 *
 * @property int $id
 * @property int $seq
 * @property int $first_entry_id
 * @property int $last_entry_id
 * @property int $entries
 * @property string $root
 * @property string|null $previous_digest
 * @property string $ring
 * @property string $key_id
 * @property string $algorithm
 * @property string $mac
 * @property CarbonImmutable $created_at
 */
final class Checkpoint extends Model
{
    /** @use HasFactory<CheckpointFactory> */
    use HasFactory;

    use StoresUtc;

    public const UPDATED_AT = null;

    protected $table = 'sentinel_checkpoints';

    protected $guarded = [];

    /**
     * Append-only, enforced where every Eloquent update and delete runs — model events muted
     * (updateQuietly(), deleteQuietly(), withoutEvents()) or not. Inserts stay allowed.
     *
     * @param  Builder<static>  $query
     */
    protected function performUpdate(Builder $query): never
    {
        throw LedgerIsAppendOnlyException::update($this->getTable());
    }

    protected function performDeleteOnModel(): never
    {
        throw LedgerIsAppendOnlyException::delete($this->getTable());
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'seq' => 'integer',
            'first_entry_id' => 'integer',
            'last_entry_id' => 'integer',
            'entries' => 'integer',
            'created_at' => UtcDateTime::class,
        ];
    }

    protected static function newFactory(): CheckpointFactory
    {
        return CheckpointFactory::new();
    }
}
