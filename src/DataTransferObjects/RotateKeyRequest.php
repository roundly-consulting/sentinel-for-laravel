<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Enums\Algorithm;

final readonly class RotateKeyRequest
{
    public function __construct(
        public string $ring,
        public ?Algorithm $algorithm = null,
        public ?CarbonImmutable $activatesAt = null,
    ) {}
}
