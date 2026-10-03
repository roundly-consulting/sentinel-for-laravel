<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency\Stores;

use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Log\LogManager;
use RoundlyConsulting\Crypto\Random\Csprng;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotencyDecision;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\Enums\IdempotencyOutcome;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Idempotency\IdempotencyRecord;
use RoundlyConsulting\Sentinel\Idempotency\ResponseSnapshot;
use RoundlyConsulting\Sentinel\Idempotency\ResponseVault;
use RoundlyConsulting\Sentinel\Idempotency\StateMachine;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\LockableCache;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Idempotency keys in a cache store that supports atomic locks: every read-modify-write runs
 * under `lock("sentinel:idem:{digest}:lock")`, with the same decision table as the database
 * store. Entries expire with the key's TTL, so there is nothing to prune.
 *
 * @internal
 */
final readonly class CacheIdempotencyStore implements IdempotencyStore
{
    /** The store a stored response is bound to. */
    private const string NAME = 'cache';

    private LockProvider $locks;

    public function __construct(
        private Repository $cache,
        private ResponseVault $vault,
        private LogManager $log,
        private Csprng $random = new Csprng,
    ) {
        $this->locks = LockableCache::locks($cache, 'idempotency.cache_store');
    }

    public function begin(IdempotentRequest $request): IdempotencyDecision
    {
        return $this->locked($request->keyDigest, function () use ($request): IdempotencyDecision {
            try {
                $record = $this->load($request->keyDigest);
            } catch (CorruptRecordException) {
                // An edited entry fails closed, as in the database store: never run the handler
                // twice on a guess.
                return new IdempotencyDecision(IdempotencyOutcome::Unavailable);
            }

            $now = Clock::now();
            $transition = StateMachine::begin(
                $record, $request, $now, $this->random->token(43), $request->leaseSeconds(),
                fn (string $payload): ?ResponseSnapshot => $this->vault->open($payload, $request, self::NAME),
            );

            if ($transition->record !== null) {
                $this->save($request->keyDigest, $transition->record, $now);
            }

            return $transition->decision;
        }) ?? new IdempotencyDecision(IdempotencyOutcome::InProgress, retryAfter: 1);
    }

    public function complete(IdempotentRequest $request, ResponseSnapshot $snapshot): bool
    {
        $completed = $this->locked($request->keyDigest, function () use ($request, $snapshot): bool {
            $record = $this->loadOrNull($request->keyDigest);

            if ($record === null || ! StateMachine::owns($record, $request)) {
                return false;
            }

            $now = Clock::now();
            $this->save($request->keyDigest, $record->completedWith(
                $snapshot->replayable ? $this->vault->seal($snapshot, $request, self::NAME) : null, $snapshot->status, $snapshot->replayable, $now,
            ), $now);

            return true;
        });

        if ($completed !== true) {
            $this->log->channel(Settings::logChannel())->warning('Sentinel: an idempotent request finished after losing its key to another request.', ['scope' => $request->scope]);
        }

        return $completed === true;
    }

    public function release(IdempotentRequest $request): void
    {
        $this->locked($request->keyDigest, function () use ($request): bool {
            return StateMachine::owns($this->loadOrNull($request->keyDigest), $request) && $this->cache->forget(self::key($request->keyDigest));
        });
    }

    public function forget(string $keyDigest): bool
    {
        $existed = $this->cache->has(self::key($keyDigest));
        $this->cache->forget(self::key($keyDigest));

        return $existed;
    }

    public function prune(CarbonImmutable $now): int
    {
        return 0;
    }

    /**
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T|null null when the key's lock could not be taken in time
     */
    private function locked(string $digest, Closure $callback): mixed
    {
        try {
            return $this->locks->lock(self::key($digest).':lock', 10)->block(5, $callback);
        } catch (LockTimeoutException) {
            return null;
        }
    }

    /**
     * The stored record, null when there is none.
     *
     * @throws CorruptRecordException when an entry exists but is not a readable record
     */
    private function load(string $digest): ?IdempotencyRecord
    {
        $stored = $this->cache->get(self::key($digest));

        if ($stored === null) {
            return null;
        }

        if (! is_array($stored)) {
            throw CorruptRecordException::idempotency('not a record');
        }

        $cast = new UtcDateTime;
        $model = new IdempotencyKey;

        return new IdempotencyRecord(
            (string) ($stored['scope'] ?? ''), (string) ($stored['fingerprint'] ?? ''), ($stored['completed'] ?? false) === true,
            (string) ($stored['owner_token'] ?? ''),
            $cast->get($model, 'locked_until', $stored['locked_until'] ?? null, []) ?? throw CorruptRecordException::idempotency('no lease'),
            isset($stored['response']) && is_string($stored['response']) ? $stored['response'] : null,
            isset($stored['response_status']) && is_int($stored['response_status']) ? $stored['response_status'] : null,
            ($stored['replayable'] ?? true) === true,
            $cast->get($model, 'completed_at', $stored['completed_at'] ?? null, []),
            $cast->get($model, 'expires_at', $stored['expires_at'] ?? null, []) ?? throw CorruptRecordException::idempotency('no expiry'),
            $cast->get($model, 'created_at', $stored['created_at'] ?? null, []) ?? throw CorruptRecordException::idempotency('no creation time'),
        );
    }

    /**
     * The stored record when it is readable: an edited entry is owned by nobody, so it can be
     * neither completed nor released (it expires with its TTL).
     */
    private function loadOrNull(string $digest): ?IdempotencyRecord
    {
        try {
            return $this->load($digest);
        } catch (CorruptRecordException) {
            return null;
        }
    }

    private function save(string $digest, IdempotencyRecord $record, CarbonImmutable $now): void
    {
        $this->cache->put(self::key($digest), [
            'scope' => $record->scope,
            'fingerprint' => $record->fingerprint,
            'completed' => $record->completed,
            'owner_token' => $record->ownerToken,
            'locked_until' => Clock::database($record->lockedUntil),
            'response' => $record->response,
            'response_status' => $record->responseStatus,
            'replayable' => $record->replayable,
            'completed_at' => $record->completedAt === null ? null : Clock::database($record->completedAt),
            'expires_at' => Clock::database($record->expiresAt),
            'created_at' => Clock::database($record->createdAt),
        ], max(1, $record->keepUntil()->getTimestamp() - $now->getTimestamp()));
    }

    private static function key(string $digest): string
    {
        return 'sentinel:idem:'.$digest;
    }
}
