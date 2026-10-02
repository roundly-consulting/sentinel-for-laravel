<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Idempotency;

use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotencyDecision;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;

/**
 * Own an idempotency key for an HTTP request, or learn why not (the middleware path).
 *
 * @internal
 */
final readonly class BeginIdempotentRequestAction
{
    public function __construct(private IdempotencyStore $store) {}

    public function execute(IdempotentRequest $request): IdempotencyDecision
    {
        return $this->store->begin($request);
    }
}
