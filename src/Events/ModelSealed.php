<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use RoundlyConsulting\Sentinel\Enums\SealEvent;

/**
 * A seal was written (after commit). Scalars only — never values or key material.
 */
final readonly class ModelSealed implements ShouldDispatchAfterCommit
{
    public function __construct(
        public string $sealableType,
        public int|string $sealableId,
        public string $seal,
        public int $version,
        public string $keyId,
        public SealEvent $event,
        public ?string $actorType = null,
        public int|string|null $actorId = null,
    ) {}
}
