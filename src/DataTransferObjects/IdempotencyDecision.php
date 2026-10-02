<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Enums\IdempotencyOutcome;
use RoundlyConsulting\Sentinel\Idempotency\ResponseSnapshot;

/**
 * A store's decision for an idempotent request.
 *
 * @internal
 */
final readonly class IdempotencyDecision
{
    public function __construct(
        public IdempotencyOutcome $outcome,
        public ?ResponseSnapshot $replay = null,
        public ?int $retryAfter = null,
        public ?string $ownerToken = null,
        public ?CarbonImmutable $firstSeenAt = null,
    ) {}
}
