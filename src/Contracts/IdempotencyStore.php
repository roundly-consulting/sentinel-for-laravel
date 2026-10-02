<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Contracts;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotencyDecision;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\Idempotency\ResponseSnapshot;

/**
 * Where idempotency keys live. Built in: `database` (default) and `cache` (a lock-capable
 * store); bind your own implementation of this contract to replace them. Every method must be
 * atomic per key: two concurrent `begin()` calls for one key yield exactly one `proceed`.
 */
interface IdempotencyStore
{
    /**
     * Own the key (proceed), or say why not: replay, in progress, reused, unavailable.
     */
    public function begin(IdempotentRequest $request): IdempotencyDecision;

    /**
     * Store the response — only while the request still owns the key; false when the lease
     * was lost to another request.
     */
    public function complete(IdempotentRequest $request, ResponseSnapshot $snapshot): bool;

    /**
     * Give the key back (the handler failed): the client may retry.
     */
    public function release(IdempotentRequest $request): void;

    public function forget(string $keyDigest): bool;

    /**
     * Remove expired keys; how many went.
     */
    public function prune(CarbonImmutable $now): int;
}
