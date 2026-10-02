<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use RoundlyConsulting\Sentinel\Enums\VerificationStatus;

final readonly class StatusCount
{
    public function __construct(
        public VerificationStatus $status,
        public int $count,
    ) {}
}
