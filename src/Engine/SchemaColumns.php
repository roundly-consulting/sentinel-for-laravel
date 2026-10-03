<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Engine;

use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use WeakMap;

/**
 * The per-request memo of table column listings, keyed by (connection, table). A stored
 * manifest that names a column outside the current seal (a row sealed under an older, wider
 * definition, or an edited one) is checked against the schema; without the memo, every such
 * verification on retrieve or scan would cost one more schema query.
 *
 * Bound **scoped**, never process-static: Laravel drops it between Octane requests and queued
 * jobs, so a migration that runs between units of work is always seen.
 *
 * @internal
 */
final class SchemaColumns
{
    /** @var WeakMap<Connection, array<string, list<string>>> */
    private WeakMap $listings;

    public function __construct()
    {
        $this->listings = new WeakMap;
    }

    /**
     * Whether every given column exists in the model's table.
     *
     * @param  list<string>  $columns
     */
    public function exist(Model $model, array $columns): bool
    {
        $connection = $model->getConnection();
        $table = $model->getTable();
        $tables = $this->listings[$connection] ?? [];

        if (! isset($tables[$table])) {
            $tables[$table] = $connection->getSchemaBuilder()->getColumnListing($table);
            $this->listings[$connection] = $tables;
        }

        return array_diff($columns, $tables[$table]) === [];
    }
}
