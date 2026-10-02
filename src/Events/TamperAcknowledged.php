<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;

/**
 * An out-of-band change was acknowledged and re-sealed (after commit).
 */
final readonly class TamperAcknowledged implements ShouldDispatchAfterCommit
{
    /**
     * @param  list<string>|null  $changedAttributes
     */
    public function __construct(
        public string $sealableType,
        public int|string $sealableId,
        public string $seal,
        public int $version,
        public VerificationStatus $previousStatus,
        public ?array $changedAttributes,
        public string $reason,
        public ?string $actorType,
        public int|string|null $actorId,
    ) {}
}
