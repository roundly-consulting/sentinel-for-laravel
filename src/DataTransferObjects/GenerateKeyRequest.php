<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyDestination;

final readonly class GenerateKeyRequest
{
    public function __construct(
        public string $ring,
        public Algorithm $algorithm,
        public ?string $keyId = null,
        public KeyDestination $destination = KeyDestination::Database,
        public ?CarbonImmutable $activatesAt = null,
        public ?Model $owner = null,
        public ?string $label = null,
    ) {}
}
