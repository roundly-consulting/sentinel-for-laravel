<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Testing;

use RoundlyConsulting\Sentinel\Enums\VerificationStatus;

/**
 * A verification status scripted on {@see SentinelFake}.
 */
final readonly class FakedStatus
{
    /**
     * @param  list<string>|null  $changed
     */
    public function __construct(
        public VerificationStatus $status,
        public ?array $changed,
        public ?string $reason = null,
    ) {}
}
