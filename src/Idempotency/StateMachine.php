<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency;

use Carbon\CarbonImmutable;
use Closure;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotencyDecision;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\Enums\IdempotencyOutcome;

/**
 * The idempotency decision table (plan §4.9.5), shared by every store — database, cache and
 * the fake's in-memory one — so they can never disagree. Each store calls it while holding its
 * own lock on the key (a row lock, a cache lock).
 *
 *     no record / expired      → own it (proceed) — never while a live lease holds it
 *     another fingerprint      → reused (422)
 *     completed, replayable    → replay
 *     completed, unreplayable  → unavailable (409)
 *     processing, lease valid  → in progress (409 + Retry-After)
 *     processing, lease over   → take over (proceed)
 *
 * @internal
 */
final class StateMachine
{
    /**
     * @param  Closure(string): ?ResponseSnapshot  $open  decrypt/parse a stored response (null = unusable)
     */
    public static function begin(?IdempotencyRecord $record, IdempotentRequest $request, CarbonImmutable $now, string $token, int $lockSeconds, Closure $open): Transition
    {
        if ($record === null || $record->expired($now)) {
            return new Transition(
                new IdempotencyDecision(IdempotencyOutcome::Proceed, ownerToken: $token, firstSeenAt: $now),
                IdempotencyRecord::owned($request->scope, $request->fingerprint, $token, $now, $lockSeconds, $request->ttl),
            );
        }

        if (! ConstantTime::equals($record->fingerprint, $request->fingerprint)) {
            return new Transition(new IdempotencyDecision(IdempotencyOutcome::Reused, firstSeenAt: $record->createdAt));
        }

        if ($record->completed) {
            $snapshot = $record->replayable && $record->response !== null ? $open($record->response) : null;

            return new Transition($snapshot === null
                ? new IdempotencyDecision(IdempotencyOutcome::Unavailable, firstSeenAt: $record->createdAt)
                : new IdempotencyDecision(IdempotencyOutcome::Replay, $snapshot, firstSeenAt: $record->createdAt));
        }

        if ($record->lockedUntil->gt($now)) {
            $retryAfter = max(1, (int) ceil((float) $record->lockedUntil->format('U.u') - (float) $now->format('U.u')));

            return new Transition(new IdempotencyDecision(IdempotencyOutcome::InProgress, retryAfter: $retryAfter, firstSeenAt: $record->createdAt));
        }

        // The owner's lease ran out (it crashed or is too slow): take the key over.
        return new Transition(
            new IdempotencyDecision(IdempotencyOutcome::Proceed, ownerToken: $token, firstSeenAt: $record->createdAt),
            $record->leasedTo($token, $now, $lockSeconds),
        );
    }

    /**
     * Whether the request still owns the key (only an owner may complete or release it).
     */
    public static function owns(?IdempotencyRecord $record, IdempotentRequest $request): bool
    {
        return $record !== null && ! $record->completed && $request->ownerToken !== null && ConstantTime::equals($record->ownerToken, $request->ownerToken);
    }
}
