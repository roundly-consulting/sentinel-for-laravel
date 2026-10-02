<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;

/**
 * A verification found a model not intact (dispatched synchronously, wherever it happened).
 * Attribute *names* only, never values.
 */
final readonly class TamperDetected
{
    /**
     * @param  list<string>|null  $changedAttributes
     */
    public function __construct(
        public string $sealableType,
        public int|string $sealableId,
        public string $seal,
        public VerificationStatus $status,
        public ?string $reason,
        public ?array $changedAttributes,
        public VerificationContext $context,
        public ?string $keyId,
    ) {}
}
