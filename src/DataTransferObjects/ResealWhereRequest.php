<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Closure;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Acknowledge every row a query selects (a bulk acknowledgement): each non-intact row is
 * re-sealed with the reason and actor in its MAC'd ledger entry; intact rows are untouched.
 */
final readonly class ResealWhereRequest
{
    /**
     * @param  class-string<Model>  $model
     * @param  (Closure(Builder<Model>): mixed)|Builder<Model>  $query
     */
    public function __construct(
        public string $model,
        public Closure|Builder $query,
        public string $reason,
        public ?Model $actor = null,
        public ?string $seal = null,
        public int $chunk = 500,
    ) {}
}
