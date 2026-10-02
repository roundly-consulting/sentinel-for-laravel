<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

/**
 * `Sentinel::withoutSealing()` began (synchronous): writes inside are not sealed.
 */
final readonly class SealingSuspended
{
    public function __construct(
        public string $reason,
        public ?string $actorType,
        public int|string|null $actorId,
    ) {}
}
