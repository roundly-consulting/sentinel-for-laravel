<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use RoundlyConsulting\Sentinel\Enums\Algorithm;

/**
 * Dispatched after commit. Scalars only — never key material.
 */
final readonly class KeyRevoked implements ShouldDispatchAfterCommit
{
    public function __construct(
        public string $ring,
        public string $keyId,
        public Algorithm $algorithm,
        public string $reason,
        public ?string $actorType = null,
        public int|string|null $actorId = null,
    ) {}
}
