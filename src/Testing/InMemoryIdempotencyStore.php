<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Testing;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Random\Csprng;
use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotencyDecision;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\Idempotency\IdempotencyRecord;
use RoundlyConsulting\Sentinel\Idempotency\ResponseSnapshot;
use RoundlyConsulting\Sentinel\Idempotency\StateMachine;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * The fake's idempotency store: the real decision table (replay, 409, 422, take-over after the
 * lease) over a PHP array. One per fake instance, so nothing leaks between tests.
 */
final class InMemoryIdempotencyStore implements IdempotencyStore
{
    /** @var array<string, IdempotencyRecord> */
    private array $records = [];

    /** @var array<string, ResponseSnapshot> */
    private array $responses = [];

    public function begin(IdempotentRequest $request): IdempotencyDecision
    {
        $now = Clock::now();
        $transition = StateMachine::begin(
            $this->records[$request->keyDigest] ?? null, $request, $now, (new Csprng)->token(43), Settings::idempotencyLockSeconds(),
            fn (string $id): ?ResponseSnapshot => $this->responses[$id] ?? null,
        );

        if ($transition->record !== null) {
            $this->records[$request->keyDigest] = $transition->record;
        }

        return $transition->decision;
    }

    public function complete(IdempotentRequest $request, ResponseSnapshot $snapshot): bool
    {
        $record = $this->records[$request->keyDigest] ?? null;

        if ($record === null || ! StateMachine::owns($record, $request)) {
            return false;
        }

        $this->responses[$request->keyDigest] = $snapshot;
        $this->records[$request->keyDigest] = $record->completedWith($snapshot->replayable ? $request->keyDigest : null, $snapshot->status, $snapshot->replayable, Clock::now());

        return true;
    }

    public function release(IdempotentRequest $request): void
    {
        if (StateMachine::owns($this->records[$request->keyDigest] ?? null, $request)) {
            unset($this->records[$request->keyDigest]);
        }
    }

    public function forget(string $keyDigest): bool
    {
        $existed = isset($this->records[$keyDigest]);
        unset($this->records[$keyDigest], $this->responses[$keyDigest]);

        return $existed;
    }

    public function prune(CarbonImmutable $now): int
    {
        $expired = array_keys(array_filter($this->records, static fn (IdempotencyRecord $record): bool => $record->expired($now)));

        foreach ($expired as $digest) {
            unset($this->records[$digest], $this->responses[$digest]);
        }

        return count($expired);
    }
}
