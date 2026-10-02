<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;

final readonly class UnsealRequest
{
    public function __construct(
        public Model $model,
        public string $seal,
        public string $reason,
        public ?Model $actor = null,
    ) {}
}
