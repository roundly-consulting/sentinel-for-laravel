<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Ledger;

use JsonException;
use RoundlyConsulting\Sentinel\Canonical\LedgerMessage;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * A stored ledger entry read back into its canonical document, from the raw columns only.
 *
 * @internal
 */
final class StoredEntry
{
    /**
     * The entry's `sentinel.ledger/1` document; null when a column is unreadable. The
     * algorithm is the one given (a key's — never trusted from the row), else the stored one;
     * the identity is the given sealable's, else the stored columns'.
     */
    public static function message(LedgerEntry $entry, ?Algorithm $algorithm = null, ?string $type = null, ?string $id = null): ?LedgerMessage
    {
        $algorithm ??= Algorithm::tryFrom((string) $entry->getRawOriginal('algorithm'));
        $event = SealEvent::tryFrom((string) $entry->getRawOriginal('event'));
        $status = $entry->getRawOriginal('previous_status');
        $previousStatus = $status === null ? null : VerificationStatus::tryFrom((string) $status);
        $changed = self::changed($entry->getRawOriginal('changed'));
        $actorType = $entry->getRawOriginal('actor_type');
        $sealMac = $entry->getRawOriginal('seal_mac');
        $previous = $entry->getRawOriginal('previous_digest');
        $reason = $entry->getRawOriginal('reason');

        try {
            $at = (new UtcDateTime)->get($entry, 'occurred_at', $entry->getRawOriginal('occurred_at'), []);
        } catch (CorruptRecordException) {
            $at = null;
        }

        // An actor id without its type (or the reverse) is never written: the row was edited.
        $actorHalf = ($actorType === null) !== ($entry->getRawOriginal('actor_id') === null);

        if ($algorithm === null || $event === null || ($status !== null && $previousStatus === null) || $changed === false || $at === null || $actorHalf) {
            return null;
        }

        return new LedgerMessage(
            Settings::context(),
            $type ?? (string) $entry->getRawOriginal('sealable_type'),
            $id ?? (string) $entry->getRawOriginal('sealable_id'),
            (string) $entry->getRawOriginal('seal'),
            (int) $entry->getRawOriginal('version'), $event, (string) $entry->getRawOriginal('ring'), (string) $entry->getRawOriginal('key_id'),
            $algorithm, $sealMac === null ? null : (string) $sealMac, $previous === null ? null : (string) $previous, $changed,
            $previousStatus, $actorType === null ? null : $actorType.':'.$entry->getRawOriginal('actor_id'),
            $reason === null ? null : (string) $reason, $at,
        );
    }

    /**
     * The raw columns the document covers, in a fixed order (the chain's fallback for an
     * unreadable row).
     *
     * @return list<string|null>
     */
    public static function rawColumns(LedgerEntry $entry): array
    {
        $columns = [];

        foreach (['sealable_type', 'sealable_id', 'seal', 'event', 'version', 'ring', 'key_id', 'algorithm', 'seal_mac', 'previous_digest', 'changed', 'previous_status', 'actor_type', 'actor_id', 'reason', 'occurred_at'] as $column) {
            $value = $entry->getRawOriginal($column);
            $columns[] = $value === null ? null : (is_scalar($value) ? (string) $value : get_debug_type($value));
        }

        return $columns;
    }

    /**
     * @return list<string>|false|null false when the stored JSON is not a list of names
     */
    private static function changed(mixed $raw): array|false|null
    {
        if ($raw === null) {
            return null;
        }

        try {
            $decoded = json_decode((string) $raw, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return false;
        }

        if (! is_array($decoded) || ! array_is_list($decoded)) {
            return false;
        }

        $names = [];

        foreach ($decoded as $name) {
            if (! is_string($name)) {
                return false;
            }

            $names[] = $name;
        }

        return $names;
    }
}
