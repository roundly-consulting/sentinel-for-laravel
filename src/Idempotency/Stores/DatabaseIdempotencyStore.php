<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency\Stores;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
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
use RoundlyConsulting\Sentinel\Support\CountsExpired;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Idempotency keys in `sentinel_idempotency_keys` (plan §9.8). The first request wins the
 * unique digest with `INSERT … ON CONFLICT DO NOTHING` (no check-then-act); every later one
 * decides under the row lock, and a takeover is a compare-and-swap on the owner token.
 * Completing and releasing only ever touch a row the request still owns.
 *
 * @internal
 */
final readonly class DatabaseIdempotencyStore implements CountsExpired, IdempotencyStore
{
    /** The store a stored response is bound to. */
    private const string NAME = 'database';

    public function __construct(
        private ResponseVault $vault,
        private LogManager $log,
        private Csprng $random = new Csprng,
    ) {}

    public function begin(IdempotentRequest $request): IdempotencyDecision
    {
        $now = Clock::now();
        $token = $this->random->token(43);
        $lock = $request->leaseSeconds();
        $owned = IdempotencyRecord::owned($request->scope, $request->fingerprint, $token, $now, $lock, $request->ttl);

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $inserted = IdempotencyKey::query()->insertOrIgnore(['key_digest' => $request->keyDigest, ...self::columns($owned, $now)]);

            if ($inserted === 1) {
                return new IdempotencyDecision(IdempotencyOutcome::Proceed, ownerToken: $token, firstSeenAt: $now);
            }

            $decision = (new IdempotencyKey)->getConnection()->transaction(
                fn (): ?IdempotencyDecision => $this->decide($request, $now, $token, $lock),
            );

            // null: the row vanished between the insert and the lock (pruned, released) — again.
            if ($decision !== null) {
                return $decision;
            }
        }

        return new IdempotencyDecision(IdempotencyOutcome::InProgress, retryAfter: 1);
    }

    public function complete(IdempotentRequest $request, ResponseSnapshot $snapshot): bool
    {
        $now = Clock::now();

        $affected = $request->ownerToken === null ? 0 : IdempotencyKey::query()
            ->where('key_digest', $request->keyDigest)
            ->where('owner_token', $request->ownerToken)
            ->where('status', IdempotencyKey::PROCESSING)
            ->toBase()
            ->update([
                'status' => IdempotencyKey::COMPLETED,
                'response' => $snapshot->replayable ? $this->vault->seal($snapshot, $request, self::NAME) : null,
                'response_status' => $snapshot->status,
                'replayable' => $snapshot->replayable,
                'completed_at' => Clock::database($now),
                'updated_at' => Clock::database($now),
            ]);

        if ($affected !== 1) {
            $this->log->channel(Settings::logChannel())->warning('Sentinel: an idempotent request finished after losing its key to another request.', ['scope' => $request->scope]);

            return false;
        }

        return true;
    }

    public function release(IdempotentRequest $request): void
    {
        if ($request->ownerToken !== null) {
            IdempotencyKey::query()
                ->where('key_digest', $request->keyDigest)
                ->where('owner_token', $request->ownerToken)
                ->where('status', IdempotencyKey::PROCESSING)
                ->toBase()
                ->delete();
        }
    }

    public function forget(string $keyDigest): bool
    {
        return IdempotencyKey::query()->where('key_digest', $keyDigest)->toBase()->delete() > 0;
    }

    public function prune(CarbonImmutable $now): int
    {
        return self::expired($now)->toBase()->delete();
    }

    public function countExpired(CarbonImmutable $now): int
    {
        return self::expired($now)->count();
    }

    /**
     * Past their TTL — and not held by a live lease (the request that owns one is running).
     *
     * @return Builder<IdempotencyKey>
     */
    private static function expired(CarbonImmutable $now): Builder
    {
        $at = Clock::database($now);

        return IdempotencyKey::query()->where('expires_at', '<=', $at)->where(
            static fn (Builder $query) => $query->where('status', IdempotencyKey::COMPLETED)->orWhere('locked_until', '<=', $at),
        );
    }

    private function decide(IdempotentRequest $request, CarbonImmutable $now, string $token, int $lock): ?IdempotencyDecision
    {
        $row = IdempotencyKey::query()->where('key_digest', $request->keyDigest)->lockForUpdate()->first();

        if ($row === null) {
            return null;
        }

        $record = $this->record($row);

        // An edited row fails closed: never run the handler twice on a guess.
        if ($record === null) {
            return new IdempotencyDecision(IdempotencyOutcome::Unavailable);
        }

        $transition = StateMachine::begin($record, $request, $now, $token, $lock, fn (string $payload): ?ResponseSnapshot => $this->vault->open($payload, $request, self::NAME));

        if ($transition->record === null) {
            return $transition->decision;
        }

        $swapped = IdempotencyKey::query()
            ->whereKey($row->getKey())
            ->where('owner_token', $record->ownerToken)
            ->toBase()
            ->update(self::columns($transition->record, $now));

        return $swapped === 1 ? $transition->decision : new IdempotencyDecision(IdempotencyOutcome::InProgress, retryAfter: 1);
    }

    private function record(IdempotencyKey $row): ?IdempotencyRecord
    {
        $cast = new UtcDateTime;

        try {
            $lockedUntil = $cast->get($row, 'locked_until', $row->getRawOriginal('locked_until'), []);
            $expiresAt = $cast->get($row, 'expires_at', $row->getRawOriginal('expires_at'), []);
            $createdAt = $cast->get($row, 'created_at', $row->getRawOriginal('created_at'), []);
            $completedAt = $cast->get($row, 'completed_at', $row->getRawOriginal('completed_at'), []);
        } catch (CorruptRecordException) {
            return null;
        }

        $response = $row->getRawOriginal('response');
        $status = $row->getRawOriginal('response_status');

        if ($lockedUntil === null || $expiresAt === null) {
            return null;
        }

        return new IdempotencyRecord(
            (string) $row->getRawOriginal('scope'),
            (string) $row->getRawOriginal('fingerprint'),
            $row->getRawOriginal('status') === IdempotencyKey::COMPLETED,
            (string) $row->getRawOriginal('owner_token'),
            $lockedUntil,
            $response === null ? null : (string) $response,
            $status === null ? null : (int) $status,
            (bool) $row->getRawOriginal('replayable'),
            $completedAt,
            $expiresAt,
            $createdAt ?? $lockedUntil,
        );
    }

    /**
     * @return array<string, string|int|bool|null>
     */
    private static function columns(IdempotencyRecord $record, CarbonImmutable $now): array
    {
        return [
            'scope' => $record->scope,
            'fingerprint' => $record->fingerprint,
            'status' => $record->completed ? IdempotencyKey::COMPLETED : IdempotencyKey::PROCESSING,
            'owner_token' => $record->ownerToken,
            'locked_until' => Clock::database($record->lockedUntil),
            'response' => $record->response,
            'response_status' => $record->responseStatus,
            'replayable' => $record->replayable,
            'completed_at' => $record->completedAt === null ? null : Clock::database($record->completedAt),
            'expires_at' => Clock::database($record->expiresAt),
            'created_at' => Clock::database($record->createdAt),
            'updated_at' => Clock::database($now),
        ];
    }
}
