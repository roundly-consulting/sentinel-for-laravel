<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Engine;

use Illuminate\Database\Eloquent\Model;

/**
 * Raw driver values of a model's row, straight from the database (plan §4.3.1): no casts,
 * no global scopes (soft-deleted rows included). Sealing reads under `FOR UPDATE` inside the
 * sealing transaction, so the seal covers exactly what the database holds — defaults,
 * triggers and engine rewrites included — and MySQL REPEATABLE READ cannot serve a stale
 * snapshot.
 *
 * Seals with a scope or computed fields read the whole row: their closures run on a model
 * hydrated from it ({@see DocumentBuilder}), never on the caller's in-memory instance (which
 * lacks database defaults and may hold unsaved changes).
 *
 * @internal
 */
final class ReadBack
{
    /**
     * @param  list<string>  $columns
     * @return array<string, mixed>|null the raw row, or null when it does not exist
     */
    public function row(Model $model, array $columns, bool $lock = false): ?array
    {
        $query = $model->newQueryWithoutScopes()->whereKey($model->getKey())->toBase()
            ->select(in_array('*', $columns, true) ? ['*'] : array_values(array_unique([$model->getKeyName(), ...$columns])));

        if ($lock) {
            $query->lockForUpdate();
        }

        $row = $query->first();

        return $row === null ? null : get_object_vars($row);
    }
}
