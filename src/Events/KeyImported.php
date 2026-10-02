<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use RoundlyConsulting\Sentinel\Enums\Algorithm;

/**
 * Key material was imported into a ring's database store (a partner onboarded, or a key
 * moved from the environment). Dispatched after commit. Scalars only — never key material.
 * `signing` tells whether the imported key may sign; the actor is the authenticated user
 * (null in the console).
 */
final readonly class KeyImported implements ShouldDispatchAfterCommit
{
    public function __construct(
        public string $ring,
        public string $keyId,
        public Algorithm $algorithm,
        public bool $signing,
        public ?string $actorType = null,
        public int|string|null $actorId = null,
    ) {}
}
