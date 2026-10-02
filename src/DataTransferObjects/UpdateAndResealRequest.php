<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Closure;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * A deliberate mass update: every selected row must verify intact first (else nothing is
 * written), then the query-builder update runs and each row is re-sealed with the reason.
 */
final readonly class UpdateAndResealRequest
{
    /**
     * @param  class-string<Model>  $model
     * @param  (Closure(Builder<Model>): mixed)|Builder<Model>  $query
     * @param  array<string, mixed>  $values
     */
    public function __construct(
        public string $model,
        public Closure|Builder $query,
        public array $values,
        public string $reason,
        public ?Model $actor = null,
        public int $chunk = 500,
    ) {}
}
