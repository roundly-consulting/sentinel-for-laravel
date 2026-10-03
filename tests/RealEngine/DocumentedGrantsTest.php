<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Testing\Database\DriverMatrix;

/**
 * The least-privilege grants database-schema.md documents for the application user: SELECT and
 * INSERT on the ledger and the checkpoints, UPDATE only of `checkpoint_id` on the ledger, and the
 * one row-lock privilege the checkpoint job's `SELECT … FOR UPDATE` of the checkpoint tail needs
 * (PostgreSQL: UPDATE of any column — `seq`, MAC-bound, so an edit is detected; MySQL: LOCK
 * TABLES) — never DELETE.
 *
 * @param  bool  $rowLock  whether to grant the row-lock privilege
 * @return list<string>
 */
function documentedGrants(string $driver, string $user, bool $rowLock): array
{
    if ($driver === 'pgsql') {
        return array_values(array_filter([
            "GRANT USAGE ON SCHEMA public TO {$user}",
            "GRANT ALL ON ALL TABLES IN SCHEMA public TO {$user}",
            "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {$user}",
            "REVOKE ALL ON sentinel_ledger, sentinel_checkpoints FROM {$user}",
            "GRANT SELECT, INSERT ON sentinel_ledger, sentinel_checkpoints TO {$user}",
            "GRANT UPDATE (checkpoint_id) ON sentinel_ledger TO {$user}",
            $rowLock ? "GRANT UPDATE (seq) ON sentinel_checkpoints TO {$user}" : null,
        ]));
    }

    $database = (string) DB::connection()->getDatabaseName();
    $tables = array_map(static fn (object $row): string => (string) array_values((array) $row)[0], DB::select('SHOW TABLES'));
    $grants = [];

    foreach ($tables as $table) {
        $grants[] = match ($table) {
            'sentinel_ledger', 'sentinel_checkpoints' => "GRANT SELECT, INSERT ON `{$database}`.`{$table}` TO {$user}",
            default => "GRANT ALL ON `{$database}`.`{$table}` TO {$user}",
        };
    }

    $grants[] = "GRANT UPDATE (checkpoint_id) ON `{$database}`.`sentinel_ledger` TO {$user}";

    if ($rowLock) {
        $grants[] = "GRANT LOCK TABLES ON `{$database}`.* TO {$user}";
    }

    return $grants;
}

/**
 * Run the callback as a user holding exactly the documented grants.
 */
function asLeastPrivilegedUser(bool $rowLock, Closure $callback): mixed
{
    $driver = DriverMatrix::driver();
    $name = 'sentinel_app_'.bin2hex(random_bytes(3));
    $default = (string) config('database.default');
    $connection = config("database.connections.{$default}");

    if ($driver === 'pgsql') {
        DB::statement("CREATE ROLE {$name}");
    } else {
        DB::statement("CREATE USER '{$name}'@'%' IDENTIFIED BY 'secret-grants'");
    }

    foreach (documentedGrants($driver, $driver === 'pgsql' ? $name : "'{$name}'@'%'", $rowLock) as $grant) {
        DB::statement($grant);
    }

    try {
        if ($driver === 'pgsql') {
            DB::statement("SET ROLE {$name}");
        } else {
            config()->set("database.connections.{$default}", [...$connection, 'username' => $name, 'password' => 'secret-grants']);
            DB::purge($default);
        }

        return $callback();
    } finally {
        if ($driver === 'pgsql') {
            DB::statement('RESET ROLE');
            DB::statement("DROP OWNED BY {$name}");
            DB::statement("DROP ROLE {$name}");
        } else {
            config()->set("database.connections.{$default}", $connection);
            DB::purge($default);
            DB::statement("DROP USER '{$name}'@'%'");
        }
    }
}

it('checkpoints with exactly the documented least-privilege grants (dual-review O-38)', function (): void {
    $checkpoint = asLeastPrivilegedUser(true, static function () {
        invoice();

        return Sentinel::checkpoint();
    });

    expect($checkpoint?->seq)->toBe(1)
        ->and(Sentinel::verifyLedger()->clean())->toBeTrue();
})->skip(fn (): bool => ! in_array(DriverMatrix::driver(), ['pgsql', 'mysql'], true), 'needs PostgreSQL or MySQL grants');

it('cannot lock the checkpoint tail without the row-lock privilege the docs name (dual-review O-38)', function (): void {
    $sealed = false;

    expect(static function () use (&$sealed): mixed {
        return asLeastPrivilegedUser(false, static function () use (&$sealed) {
            invoice();
            $sealed = true;

            return Sentinel::checkpoint();
        });
    })->toThrow(QueryException::class, 'sentinel_checkpoints')
        ->and($sealed)->toBeTrue();
})->skip(fn (): bool => ! in_array(DriverMatrix::driver(), ['pgsql', 'mysql'], true), 'needs PostgreSQL or MySQL grants');
