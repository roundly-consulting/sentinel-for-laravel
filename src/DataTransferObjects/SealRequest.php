<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;

/**
 * Seal a model explicitly — the input of `SealModelAction` (`Sentinel::seal()`). A null seal
 * is the model's default seal; an undeclared one throws `SealingMisconfiguredException`.
 */
final readonly class SealRequest
{
    public function __construct(
        public Model $model,
        public ?string $seal = null,
        public ?string $reason = null,
        public ?Model $actor = null,
    ) {}
}
