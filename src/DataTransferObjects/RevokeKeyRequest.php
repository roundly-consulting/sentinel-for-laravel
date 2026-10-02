<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;

final readonly class RevokeKeyRequest
{
    public function __construct(
        public string $ring,
        public string $keyId,
        public string $reason,
        public ?Model $actor = null,
    ) {}
}
