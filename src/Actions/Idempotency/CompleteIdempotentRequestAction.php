<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Idempotency;

use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\Idempotency\ResponseSnapshot;
use RoundlyConsulting\Sentinel\Support\Settings;
use Symfony\Component\HttpFoundation\Response;

/**
 * Store the response of an owned idempotent request for replays (allow-listed headers only,
 * never `Set-Cookie`; streamed, file and oversized responses are kept as unreplayable).
 * False when the request lost the key to another one meanwhile.
 *
 * @internal
 */
final readonly class CompleteIdempotentRequestAction
{
    public function __construct(private IdempotencyStore $store) {}

    public function execute(IdempotentRequest $request, Response $response): bool
    {
        return $this->store->complete($request, ResponseSnapshot::fromResponse($response, Settings::replayedHeaders(), Settings::maxResponseBytes()));
    }
}
