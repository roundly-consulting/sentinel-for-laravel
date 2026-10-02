<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency;

use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotencyDecision;

/**
 * A decision and the record to store (null = leave the record as it is).
 *
 * @internal
 */
final readonly class Transition
{
    public function __construct(
        public IdempotencyDecision $decision,
        public ?IdempotencyRecord $record = null,
    ) {}
}
