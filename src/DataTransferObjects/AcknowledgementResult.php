<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

/**
 * `acknowledged` is false when the seal was already intact (nothing written).
 */
final readonly class AcknowledgementResult
{
    public function __construct(
        public bool $acknowledged,
        public VerificationResult $before,
        public ?SealResult $seal = null,
    ) {}
}
