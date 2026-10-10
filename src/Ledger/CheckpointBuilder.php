<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Ledger;

use Illuminate\Database\DetectsConcurrencyErrors;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Sentinel\Canonical\CheckpointMessage;
use RoundlyConsulting\Sentinel\Exceptions\ConcurrentSealException;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Support\Tables;

/**
 * Folds pending ledger entries into the next checkpoint (plan §4.7.2), one batch per
 * transaction: lock the tail checkpoint, lock up to `batch_size` entries without a
 * checkpoint (by id), chain them onto the previous root, insert the MAC'd checkpoint and
 * claim the entries with a conditional UPDATE. Lock order: checkpoint tail → entries — never
 * a model or seal row, so it cannot deadlock against sealing.
 *
 * Races between two runs end in the unique `seq` index, a short claim (fewer rows updated
 * than selected) or a deadlock / serialization failure (InnoDB gap locks under REPEATABLE
 * READ); the loser rolls back and retries from a fresh tail. Late-committing
 * entries (an id lower than one already checkpointed) simply join a later checkpoint.
 *
 * @internal
 */
final readonly class CheckpointBuilder
{
    use DetectsConcurrencyErrors;

    private const int ATTEMPTS = 25;

    public function __construct(
        private KeyStoreManager $keys,
        private Signers $signers,
        private ChainHasher $chain,
    ) {}

    /**
     * The new checkpoint, or null when no entry is pending.
     */
    public function build(?string $connection, int $batchSize): ?Checkpoint
    {
        $database = Tables::checkpoint($connection)->getConnection();

        for ($attempt = 1; ; $attempt++) {
            try {
                return $database->transaction(fn (): ?Checkpoint => $this->batch($connection, $batchSize), Settings::transactionAttempts());
            } catch (UniqueConstraintViolationException|ConcurrentSealException|QueryException $exception) {
                // A deadlock victim was rolled back whole and another run committed; anything
                // else that is not a race is a real failure.
                if (! $exception instanceof ConcurrentSealException && ! $exception instanceof UniqueConstraintViolationException && ! $this->causedByConcurrencyError($exception)) {
                    throw $exception;
                }

                if ($attempt >= self::ATTEMPTS) {
                    throw $exception instanceof ConcurrentSealException ? $exception : ConcurrentSealException::checkpointConflict(Tables::connectionName($connection));
                }
            }
        }
    }

    private function batch(?string $connection, int $batchSize): ?Checkpoint
    {
        $tail = $this->lockTail($connection);
        $entries = Tables::ledgerOn($connection)->whereNull('checkpoint_id')->orderBy('id')->limit($batchSize)->lockForUpdate()->get();

        if ($entries->isEmpty()) {
            return null;
        }

        $previous = $tail === null ? null : (string) $tail->getRawOriginal('root');
        $state = $this->chain->start($previous);
        $ids = [];
        $first = PHP_INT_MAX;
        $last = 0;

        foreach ($entries as $entry) {
            $state = $this->chain->next($state, $entry);
            $ids[] = $id = (int) $entry->getKey();
            $first = min($first, $id);
            $last = max($last, $id);
        }

        $key = $this->keys->signingKey(Settings::ledgerRing());
        $at = Clock::now();
        $seq = $tail === null ? 1 : (int) $tail->getRawOriginal('seq') + 1;
        $root = $this->chain->root($state);

        $message = new CheckpointMessage(
            Settings::context(), $seq, $first, $last, count($ids), $root, $previous, $key->ring, $key->keyId, $key->algorithm(), $at,
        );

        $checkpoint = Tables::checkpoint($connection)->forceFill([
            'seq' => $seq,
            'first_entry_id' => $first,
            'last_entry_id' => $last,
            'entries' => count($ids),
            'root' => $root,
            'previous_digest' => $previous,
            'ring' => $key->ring,
            'key_id' => $key->keyId,
            'algorithm' => $key->algorithm()->value,
            'mac' => Base64Url::encode($this->signers->sign($key, Purpose::Ledger, $message->bytes())),
            'created_at' => $at,
        ]);
        $checkpoint->save();

        // The only mutation of a ledger entry; a short count means another run claimed some. The
        // ids are inlined integers, not bindings: a batch may exceed the engine's bind limit.
        $claimed = Tables::ledgerOn($connection)->whereIntegerInRaw('id', $ids)->whereNull('checkpoint_id')->toBase()->update(['checkpoint_id' => $checkpoint->getKey()]);

        if ($claimed !== count($ids)) {
            throw ConcurrentSealException::checkpointConflict(Tables::connectionName($connection));
        }

        return $checkpoint;
    }

    /**
     * Lock the newest checkpoint. Waiting for that lock can end on a row that is no longer the
     * newest (READ COMMITTED re-reads the locked row, not the ordering), so lock again until
     * two reads agree — every run then chains onto the true tail instead of failing on `seq`.
     */
    private function lockTail(?string $connection): ?Checkpoint
    {
        $tail = Tables::checkpoints($connection)->orderByDesc('seq')->lockForUpdate()->first();

        for ($attempt = 0; $attempt < self::ATTEMPTS; $attempt++) {
            $latest = Tables::checkpoints($connection)->orderByDesc('seq')->lockForUpdate()->first();

            if ($latest?->getKey() === $tail?->getKey()) {
                return $latest;
            }

            $tail = $latest;
        }

        throw ConcurrentSealException::checkpointConflict(Tables::connectionName($connection));
    }
}
