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
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;
use Throwable;

/**
 * Run a callback at most once per (key, scope) — for jobs, commands and webhooks. A repeat
 * returns the first result (replayed, as decoded JSON); a repeat with another fingerprint, or
 * while the first still runs, throws the same exceptions the HTTP middleware renders. A
 * failing callback releases the key, so it may be retried. A callback that ran but returned
 * something that cannot be stored (not JSON-encodable) never runs again: its key is
 * completed as unreplayable and `IdempotentResultException` is thrown, so a repeat is refused
 * with `IdempotentResponseUnavailableException` (409).
 */
final readonly class RunIdempotentAction
{
    public function __construct(private IdempotencyStore $store) {}

    public function execute(IdempotentCall $call): IdempotentResult
    {
        if ($call->key === '' || strlen($call->key) > 255 || strlen($call->scope) > 255) {
            throw InvalidIdempotencyKeyException::make();
        }

        $request = new IdempotentRequest(
            RequestFingerprint::key($call->scope, 'run', $call->key),
            $call->scope,
            RequestFingerprint::call($call->fingerprint),
            $call->ttl ?? Settings::idempotencyTtl(),
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

        $this->store->complete($owned, $snapshot);

        return new IdempotentResult($value, false, $firstSeenAt);
    }
}
