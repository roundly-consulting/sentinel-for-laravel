<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Idempotency;

use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;

/**
 * Give an owned idempotency key back (the handler failed or answered 5xx): the client may
 * retry with the same key.
 *
 * @internal
 */
final readonly class ReleaseIdempotentRequestAction
{
    public function __construct(private IdempotencyStore $store) {}

    public function execute(IdempotentRequest $request): void
    {
        $this->store->release($request);
    }
}
