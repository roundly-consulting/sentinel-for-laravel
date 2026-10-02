<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use Illuminate\Database\Eloquent\Model;
use JsonException;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerRecord;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Support\Tables;

/**
 * A model's seal history, newest first (as stored — verification is separate).
 */
final readonly class ReadLedgerHistoryAction
{
    public function __construct(private DefinitionRegistry $registry) {}

    /**
     * @return list<LedgerRecord>
     */
    public function execute(Model $model, string $seal, int $limit): array
    {
        $name = $this->registry->seal($model, $seal)->name;

        return array_values(Tables::entries($model, $name)
            ->orderByDesc('version')
            ->limit(max(1, min($limit, 1000)))
            ->get()
            ->map(static fn (LedgerEntry $entry): LedgerRecord => self::record($entry))
            ->all());
    }

    private static function record(LedgerEntry $entry): LedgerRecord
    {
        try {
            $occurredAt = (new UtcDateTime)->get($entry, 'occurred_at', $entry->getRawOriginal('occurred_at'), []);
        } catch (CorruptRecordException) {
            $occurredAt = null;
        }

        try {
            $changed = json_decode((string) ($entry->getRawOriginal('changed') ?? 'null'), true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $changed = null;
        }

        $checkpoint = $entry->getRawOriginal('checkpoint_id');
        $actorId = $entry->getRawOriginal('actor_id');

        return new LedgerRecord(
            (int) $entry->getKey(),
            SealEvent::tryFrom((string) $entry->getRawOriginal('event')),
            (int) $entry->getRawOriginal('version'),
            (string) $entry->getRawOriginal('ring'),
            (string) $entry->getRawOriginal('key_id'),
            is_array($changed) ? array_values(array_filter($changed, is_string(...))) : null,
            VerificationStatus::tryFrom((string) $entry->getRawOriginal('previous_status')),
            $entry->getRawOriginal('actor_type') === null ? null : (string) $entry->getRawOriginal('actor_type'),
            is_int($actorId) || is_string($actorId) ? $actorId : null,
            $entry->getRawOriginal('reason') === null ? null : (string) $entry->getRawOriginal('reason'),
            $occurredAt,
            $checkpoint === null ? null : (int) $checkpoint,
        );
    }
}
