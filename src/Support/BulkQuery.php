<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Closure;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;

/**
 * The query of a bulk operation, bound to its model class: a closure receives a fresh query
 * of the class; a builder must select that class (scoping is a security boundary — a handle
 * for invoices never touches another model's rows).
 *
 * @internal
 */
final class BulkQuery
{
    /**
     * @param  class-string<Model>  $class
     * @param  (Closure(Builder<Model>): mixed)|Builder<Model>  $query
     * @param  Builder<Model>|null  $base  what a closure receives (default: `$class::query()`)
     * @return Builder<Model>
     */
    public static function resolve(string $class, Closure|Builder $query, ?Builder $base = null): Builder
    {
        if ($query instanceof Closure) {
            $builder = $base ?? $class::query();
            $returned = $query($builder);

            $query = $returned instanceof Builder ? $returned : $builder;
        }

        if ($query->getModel()::class !== $class) {
            throw SealingMisconfiguredException::queryModelMismatch($class, $query->getModel()::class);
        }

        return $query;
    }
}
