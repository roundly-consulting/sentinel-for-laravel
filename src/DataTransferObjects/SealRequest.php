<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;

/**
 * @internal built by the manager for `SealModelAction`
 */
final readonly class SealRequest
{
    public function __construct(
        public Model $model,
        public string $seal,
        public ?string $reason = null,
        public ?Model $actor = null,
    ) {}
}
