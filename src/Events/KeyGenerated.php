<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use RoundlyConsulting\Sentinel\Enums\Algorithm;

/**
 * Dispatched after commit. Scalars only — never key material.
 */
final readonly class KeyGenerated implements ShouldDispatchAfterCommit
{
    public function __construct(
        public string $ring,
        public string $keyId,
        public Algorithm $algorithm,
    ) {}
}
