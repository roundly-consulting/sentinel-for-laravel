<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Idempotency;

use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentCall;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentResult;
use RoundlyConsulting\Sentinel\Enums\IdempotencyOutcome;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyKeyReusedException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyRequestInProgressException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotentResponseUnavailableException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotentResultException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;
use RoundlyConsulting\Sentinel\Idempotency\RequestFingerprint;
use RoundlyConsulting\Sentinel\Idempotency\ResponseSnapshot;
use RoundlyConsulting\Sentinel\Idempotency\RunLimits;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;
use Throwable;

/**
 * Run a callback at most once per (key, scope) — for jobs, commands and webhooks. Every run
 * returns the JSON round-trip of the callback's result (objects become arrays), fresh or
 * replayed, so the value has one shape on both paths; a repeat with another fingerprint, or
 * while the first still runs, throws the same exceptions the HTTP middleware renders. A
 * failing callback releases the key, so it may be retried. A callback that ran but returned
 * something that cannot be stored (not JSON-encodable, or a store that fails to keep it)
 * never runs again: its key is completed as unreplayable and the exception is thrown
 * (`IdempotentResultException` for an unencodable result), so a repeat is refused with
 * `IdempotentResponseUnavailableException` (409). The key and the scope are 1–255
 * bytes, a TTL is 60–2 592 000 seconds and a lease 1–86 400 seconds — what the `Idempotent`
 * job middleware takes (`InvalidIdempotencyKeyException` otherwise, before the store is
 * touched). A duplicate is refused while the running call's lease holds the key: give a call
 * that may run longer than `idempotency.lock_seconds` a lease above its longest run.
 */
final readonly class RunIdempotentAction
{
    public function __construct(private IdempotencyStore $store) {}

    /**
     * @throws InvalidIdempotencyKeyException for an empty or overlong key or scope, or a TTL
     *                                        outside 60–2 592 000 seconds
     */
    public function execute(IdempotentCall $call): IdempotentResult
    {
        RunLimits::check($call->key, $call->scope, $call->ttl, $call->lease);

        $request = new IdempotentRequest(
            RequestFingerprint::key($call->scope, 'run', $call->key),
            $call->scope,
            RequestFingerprint::call($call->fingerprint),
            $call->ttl ?? Settings::idempotencyTtl(),
            lease: $call->lease,
        );

        $decision = $this->store->begin($request);
        $firstSeenAt = $decision->firstSeenAt ?? Clock::now();

        if ($decision->outcome === IdempotencyOutcome::Replay && $decision->replay !== null) {
            return new IdempotentResult($decision->replay->value(), true, $firstSeenAt);
        }

        if ($decision->outcome !== IdempotencyOutcome::Proceed || $decision->ownerToken === null) {
            throw match ($decision->outcome) {
                IdempotencyOutcome::Reused => IdempotencyKeyReusedException::make(),
                IdempotencyOutcome::InProgress => IdempotencyRequestInProgressException::retryAfter($decision->retryAfter ?? 1),
                default => IdempotentResponseUnavailableException::make(),
            };
        }

        $owned = $request->ownedBy($decision->ownerToken);

        try {
            $value = ($call->callback)();
        } catch (Throwable $exception) {
            // The callback failed: nothing completed, so the call may be retried.
            $this->store->release($owned);

            throw $exception;
        }

        try {
            $snapshot = ResponseSnapshot::forValue($value);
        } catch (Throwable $exception) {
            // The callback ran — its side effect happened — but its result cannot be stored.
            // Releasing the key would let a retry repeat the side effect: complete it as
            // unreplayable instead, so a repeat is refused (409 unavailable).
            $this->store->complete($owned, ResponseSnapshot::unreplayable());

            throw IdempotentResultException::notEncodable($exception);
        }

        try {
            $this->store->complete($owned, $snapshot);
        } catch (Throwable $exception) {
            // The callback ran but its result could not be stored (no APP_KEY to encrypt it, a
            // store error): complete the key as unreplayable, as the HTTP path does, so a retry
            // after the lease is refused (409) instead of repeating the side effect.
            try {
                $this->store->complete($owned, ResponseSnapshot::unreplayable());
            } catch (Throwable $secondary) {
                report($secondary);
            }

            throw $exception;
        }

        // The JSON round-trip — exactly what a replay returns — so the value has one shape.
        return new IdempotentResult($snapshot->value(), false, $firstSeenAt);
    }
}
