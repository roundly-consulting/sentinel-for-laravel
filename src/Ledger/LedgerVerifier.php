<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Ledger;

use Closure;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Query\Builder as QueryBuilder;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Sentinel\Canonical\CheckpointMessage;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerVerifyOptions;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\LedgerWriter;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Events\LedgerIntegrityViolated;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Support\Tables;
use Throwable;

/**
 * Verifies the ledger itself (plan §9.7), per connection:
 *
 *  1. checkpoints in `seq` order — contiguous, chained, MAC'd by an accepted key, and each
 *     root recomputed over its entries (every entry MAC checked on the way);
 *  2. external anchors — not ahead of the database, matching root, valid checkpoint MAC;
 *  3. entries not yet checkpointed — MACs, and a backlog when the checkpoint job stalls;
 *     entries claiming a checkpoint that does not exist (only possible with the foreign key
 *     switched off for a session) are orphans — a violation, MAC-checked too;
 *  4. optionally every entity's ledger head — the row and its seal must still exist at that
 *     version (only a tombstone whose MAC verifies ends a history).
 *
 * Read-only. Ledger evidence is permanent, so an entry or checkpoint signed by a key that has
 * since been *retired* still verifies; a *revoked* key never does.
 *
 * @internal
 */
final readonly class LedgerVerifier
{
    public function __construct(
        private KeyStoreManager $keys,
        private Signers $signers,
        private ChainHasher $chain,
        private LedgerWriter $writer,
        private AnchorManager $anchors,
        private DefinitionRegistry $registry,
        private Dispatcher $events,
    ) {}

    public function verify(LedgerVerifyOptions $options): LedgerReport
    {
        $connections = $options->connection !== null ? [$options->connection] : Settings::ledgerConnections();
        $run = new LedgerFindings($this->registry);
        $chunk = max(1, $options->chunk);
        $names = [];

        foreach ($connections as $connection) {
            $run->connection = $names[] = Tables::connectionName($connection);
            $tail = $this->checkpoints($connection, $run, $chunk);

            foreach ($this->anchors->anchors() as $anchor) {
                $this->anchor($anchor->name(), static fn (): ?AnchorPayload => $anchor->latest($run->connection), $connection, $tail, $run);
            }

            if ($options->manualAnchor !== null && $options->manualAnchor->connection === $run->connection) {
                $this->anchor('manual', static fn (): AnchorPayload => $options->manualAnchor, $connection, $tail, $run);
            }

            $this->pending($connection, $run, $chunk);
            $this->orphans($connection, $run, $chunk);

            if ($options->entities) {
                $this->heads($connection, $run, $chunk);
            }

            $violations = $run->violationsOf($run->connection);

            if ($violations !== []) {
                $this->events->dispatch(new LedgerIntegrityViolated($run->connection, $violations));
            }
        }

        if ($options->manualAnchor !== null && ! in_array($options->manualAnchor->connection, $names, true)) {
            $run->connection = $options->manualAnchor->connection;
            $run->add(LedgerFindingKind::AnchorInvalid, 'manual anchor names an unverified connection', $options->manualAnchor->seq);
        }

        return new LedgerReport($run->checkpoints, $run->entries, $run->anchors, $run->findings);
    }

    /**
     * Every checkpoint in order; returns the tail (the highest seq seen).
     */
    private function checkpoints(?string $connection, LedgerFindings $run, int $chunk): ?Checkpoint
    {
        $previous = null;
        $expected = 1;

        foreach (Tables::checkpoints($connection)->orderBy('seq')->lazy($chunk) as $checkpoint) {
            $seq = (int) $checkpoint->getRawOriginal('seq');
            $previousDigest = $this->nullable($checkpoint->getRawOriginal('previous_digest'));
            $run->checkpoints++;

            if ($seq !== $expected) {
                $run->add(LedgerFindingKind::CheckpointGap, "expected seq {$expected}", $seq);
            }

            if ($previousDigest !== ($previous === null ? null : (string) $previous->getRawOriginal('root'))) {
                $run->add(LedgerFindingKind::ChainBroken, 'previous_digest does not match the previous checkpoint root', $seq);
            }

            $problem = $this->checkpointProblem($checkpoint);

            if ($problem !== null) {
                $run->add(LedgerFindingKind::CheckpointInvalid, $problem, $seq);
            }

            $this->recompute($connection, $checkpoint, $previousDigest, $run, $chunk);

            $previous = $checkpoint;
            $expected = $seq + 1;
        }

        return $previous;
    }

    /**
     * Rebuild a checkpoint's root over the entries it claimed, checking each entry's MAC.
     */
    private function recompute(?string $connection, Checkpoint $checkpoint, ?string $previousDigest, LedgerFindings $run, int $chunk): void
    {
        $state = $this->chain->start($previousDigest);
        $seq = (int) $checkpoint->getRawOriginal('seq');
        $ids = [];

        foreach (Tables::ledgerOn($connection)->where('checkpoint_id', $checkpoint->getKey())->lazyById($chunk) as $entry) {
            $state = $this->chain->next($state, $entry);
            $ids[] = (int) $entry->getKey();
            $this->entry($entry, $run, $seq);
        }

        $matches = $ids !== []
            && count($ids) === (int) $checkpoint->getRawOriginal('entries')
            && min($ids) === (int) $checkpoint->getRawOriginal('first_entry_id')
            && max($ids) === (int) $checkpoint->getRawOriginal('last_entry_id')
            && $this->chain->root($state) === (string) $checkpoint->getRawOriginal('root');

        if (! $matches) {
            $run->add(LedgerFindingKind::CheckpointMismatch, 'the entries no longer hash to the checkpoint root', $seq);
        }
    }

    private function entry(LedgerEntry $entry, LedgerFindings $run, ?int $seq): void
    {
        $run->entries++;

        if (! $this->writer->verify($entry, null, $run->ringsFor($entry), historic: true)) {
            $run->add(LedgerFindingKind::EntryInvalid, 'the entry MAC does not verify', $seq, $entry);
        }
    }

    /**
     * Why a checkpoint's own MAC is not trustworthy, or null.
     */
    private function checkpointProblem(Checkpoint $checkpoint): ?string
    {
        $key = $this->ledgerKey((string) $checkpoint->getRawOriginal('ring'), (string) $checkpoint->getRawOriginal('key_id'));

        if (is_string($key)) {
            return $key;
        }

        if ((string) $checkpoint->getRawOriginal('algorithm') !== $key->algorithm()->value) {
            return 'algorithm_mismatch';
        }

        try {
            $at = (new UtcDateTime)->get($checkpoint, 'created_at', $checkpoint->getRawOriginal('created_at'), [])
                ?? throw CorruptRecordException::invalidDatetime('created_at');
            $mac = Base64Url::decode((string) $checkpoint->getRawOriginal('mac'));
        } catch (CorruptRecordException|InvalidEncodingException) {
            return 'malformed';
        }

        $message = new CheckpointMessage(
            Settings::context(), (int) $checkpoint->getRawOriginal('seq'), (int) $checkpoint->getRawOriginal('first_entry_id'),
            (int) $checkpoint->getRawOriginal('last_entry_id'), (int) $checkpoint->getRawOriginal('entries'), (string) $checkpoint->getRawOriginal('root'),
            $this->nullable($checkpoint->getRawOriginal('previous_digest')), $key->ring, $key->keyId, $key->algorithm(), $at,
        );

        return $this->signers->verify($key, Purpose::Ledger, $message->bytes(), $mac) ? null : 'mac';
    }

    /**
     * A key allowed to vouch for checkpoints and anchors, or why there is none.
     */
    private function ledgerKey(string $ring, string $keyId): SealingKey|string
    {
        if (! in_array($ring, Settings::ledgerRings(), true)) {
            return 'ring_not_accepted';
        }

        // Only configured rings get here (ledgerRings() comes from the configuration).
        $lookup = $this->keys->lookup($ring, $keyId);

        return match (true) {
            $lookup->key === null => (string) $lookup->failure,
            $lookup->key->status === KeyStatus::Pending => 'pending',
            $lookup->key->status === KeyStatus::Revoked => 'revoked_key',
            default => $lookup->key,
        };
    }

    /**
     * One anchor's view against the database: never ahead, same root, a valid checkpoint MAC.
     *
     * @param  Closure(): ?AnchorPayload  $latest
     */
    private function anchor(string $name, Closure $latest, ?string $connection, ?Checkpoint $tail, LedgerFindings $run): void
    {
        try {
            $payload = $latest();
        } catch (CorruptRecordException $exception) {
            $run->anchors++;
            $run->add(LedgerFindingKind::AnchorInvalid, "anchor [{$name}]: ".$exception->getMessage());

            return;
        } catch (Throwable $exception) {
            $run->add(LedgerFindingKind::AnchorUnreachable, "anchor [{$name}]: ".$exception::class);

            return;
        }

        // Write-only (a log) or nothing published yet.
        if ($payload === null) {
            return;
        }

        $run->anchors++;
        $key = $payload->connection === $run->connection ? $this->ledgerKey($payload->ring, $payload->keyId) : 'connection';

        if (is_string($key) || $payload->algorithm !== $key->algorithm()) {
            $run->add(LedgerFindingKind::AnchorInvalid, "anchor [{$name}]: ".(is_string($key) ? $key : 'algorithm_mismatch'), $payload->seq);

            return;
        }

        $tailSeq = $tail === null ? 0 : (int) $tail->getRawOriginal('seq');

        if ($payload->seq > $tailSeq) {
            $run->add(LedgerFindingKind::AnchorAhead, "anchor [{$name}] holds seq {$payload->seq}, the database {$tailSeq}", $payload->seq);

            return;
        }

        $local = Tables::checkpoints($connection)->where('seq', $payload->seq)->first();

        if ($local === null || (string) $local->getRawOriginal('root') !== $payload->root) {
            $run->add(LedgerFindingKind::AnchorMismatch, "anchor [{$name}]: the checkpoint root differs", $payload->seq);

            return;
        }

        $message = new CheckpointMessage(
            Settings::context(), $payload->seq, (int) $local->getRawOriginal('first_entry_id'), (int) $local->getRawOriginal('last_entry_id'),
            (int) $local->getRawOriginal('entries'), $payload->root, $this->nullable($local->getRawOriginal('previous_digest')),
            $payload->ring, $payload->keyId, $key->algorithm(), $payload->at,
        );

        try {
            $valid = $this->signers->verify($key, Purpose::Ledger, $message->bytes(), Base64Url::decode($payload->mac));
        } catch (InvalidEncodingException) {
            $valid = false;
        }

        if (! $valid) {
            $run->add(LedgerFindingKind::AnchorInvalid, "anchor [{$name}]: mac", $payload->seq);
        }
    }

    /**
     * Entries no checkpoint has claimed yet: their MACs, and how stale the oldest are.
     */
    private function pending(?string $connection, LedgerFindings $run, int $chunk): void
    {
        $threshold = Clock::now()->subSeconds(Settings::backlogWarningSeconds());
        $stale = 0;

        foreach (Tables::ledgerOn($connection)->whereNull('checkpoint_id')->lazyById($chunk) as $entry) {
            $this->entry($entry, $run, null);

            try {
                $occurred = (new UtcDateTime)->get($entry, 'occurred_at', $entry->getRawOriginal('occurred_at'), []);
            } catch (CorruptRecordException) {
                $occurred = null;
            }

            if ($occurred === null || $occurred->lt($threshold)) {
                $stale++;
            }
        }

        if ($stale > 0) {
            $run->add(LedgerFindingKind::Backlog, "{$stale} entries are older than ".Settings::backlogWarningSeconds().'s and not checkpointed (is sentinel:checkpoint scheduled?)');
        }
    }

    /**
     * Entries whose `checkpoint_id` names no checkpoint: neither pending nor covered by any
     * root, so nothing else would ever check them.
     */
    private function orphans(?string $connection, LedgerFindings $run, int $chunk): void
    {
        $entries = (new LedgerEntry)->getTable();
        $checkpoints = (new Checkpoint)->getTable();

        $orphans = Tables::ledgerOn($connection)->whereNotNull('checkpoint_id')->whereNotExists(static function (QueryBuilder $claimed) use ($entries, $checkpoints): void {
            $claimed->selectRaw('1')->from($checkpoints)->whereColumn("{$checkpoints}.id", "{$entries}.checkpoint_id");
        });

        foreach ($orphans->lazyById($chunk) as $entry) {
            $run->add(LedgerFindingKind::OrphanEntry, 'the entry claims checkpoint '.$entry->getRawOriginal('checkpoint_id').', which does not exist', null, $entry);
            $this->entry($entry, $run, null);
        }
    }

    /**
     * Every entity's latest ledger entry: unless it is a tombstone whose MAC verifies, the row
     * and its seal row must still exist, at that version.
     */
    private function heads(?string $connection, LedgerFindings $run, int $chunk): void
    {
        $table = (new LedgerEntry)->getTable();

        $heads = Tables::ledgerOn($connection)->whereNotExists(static function (QueryBuilder $newer) use ($table): void {
            $newer->selectRaw('1')->from("{$table} as newer")
                ->whereColumn('newer.sealable_type', "{$table}.sealable_type")
                ->whereColumn('newer.sealable_id', "{$table}.sealable_id")
                ->whereColumn('newer.seal', "{$table}.seal")
                ->whereColumn('newer.version', '>', "{$table}.version");
        });

        foreach ($heads->lazyById($chunk) as $head) {
            // The event column alone is writable: a forged tombstone must not hide a deletion.
            if (SealEvent::tryFrom((string) $head->getRawOriginal('event'))?->isTombstone() === true
                && $this->writer->verify($head, null, $run->ringsFor($head), historic: true)) {
                continue;
            }

            $type = (string) $head->getRawOriginal('sealable_type');
            $id = $head->getRawOriginal('sealable_id');
            $seal = (string) $head->getRawOriginal('seal');
            $version = (int) $head->getRawOriginal('version');
            $class = Relation::getMorphedModel($type) ?? $type;

            if (! class_exists($class) || ! is_subclass_of($class, Model::class)) {
                $run->add(LedgerFindingKind::EntityDeleted, 'the model class cannot be resolved', null, $head);

                continue;
            }

            $model = (new $class)->setConnection($connection);

            if (! $model->newQueryWithoutScopes()->whereKey($id)->exists()) {
                $run->add(LedgerFindingKind::EntityDeleted, "the row is gone without a tombstone (ledger at v{$version})", null, $head);

                continue;
            }

            $stored = Tables::sealsOn($connection)->where('sealable_type', $type)->where('sealable_id', $id)->where('seal', $seal)->value('version');

            if ($stored === null) {
                $run->add(LedgerFindingKind::SealMissing, "the seal row is gone (ledger at v{$version})", null, $head);
            } elseif ((int) $stored < $version) {
                $run->add(LedgerFindingKind::SealRolledBack, "the seal row is at v{$stored}, the ledger at v{$version}", null, $head);
            }
        }
    }

    private function nullable(mixed $value): ?string
    {
        return $value === null ? null : (string) $value;
    }
}
