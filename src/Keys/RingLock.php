<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use Closure;
use Illuminate\Database\Connection;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;

/**
 * One rotation of a key ring at a time, across processes. A rotation locks the rows of the
 * ring's keys that could still sign; an empty ring has no rows to lock, so two first rotations
 * could each store a key that signs. This lock is per ring, on the database that stores its
 * keys, and needs no table of its own:
 *
 *  - PostgreSQL: a transaction-level advisory lock, the transaction's first statement after
 *    `SET TRANSACTION ISOLATION LEVEL READ COMMITTED` (a REPEATABLE READ snapshot would be taken
 *    before the wait, and miss the key the other rotation stored). Released at commit/rollback.
 *  - MySQL / MariaDB: a named lock (`GET_LOCK`) taken before the transaction begins and released
 *    after it ends. It waits as long as a row lock would (`innodb_lock_wait_timeout`).
 *  - SQLite: none needed — one writer at a time; the loser of a race fails with "database is
 *    locked", which the transaction retries, and then sees the winner's key.
 *
 * @internal
 */
final class RingLock
{
    /** The high half of every PostgreSQL advisory lock key Sentinel takes ("SENT"). */
    private const int NAMESPACE = 0x53454E54;

    /**
     * Run `$work` in a transaction on `$connection`, holding the ring's lock throughout.
     *
     * @template T
     *
     * @param  Closure(): T  $work
     * @param  int<1, max>  $attempts
     * @return T
     */
    public static function transaction(Connection $connection, string $ring, Closure $work, int $attempts = 1): mixed
    {
        return match ($connection->getDriverName()) {
            'pgsql' => $connection->transaction(static function () use ($connection, $ring, $work): mixed {
                // Only the outermost transaction may still choose its isolation level.
                if ($connection->transactionLevel() === 1) {
                    $connection->statement('set transaction isolation level read committed');
                }

                $connection->select('select pg_advisory_xact_lock(cast(? as bigint))', [self::advisoryKey($ring)]);

                return $work();
            }, $attempts),
            'mysql', 'mariadb' => self::named($connection, $ring, static fn (): mixed => $connection->transaction($work, $attempts)),
            default => $connection->transaction($work, $attempts),
        };
    }

    /**
     * The ring's PostgreSQL advisory lock key: Sentinel's namespace over the ring's CRC-32 (a
     * collision only makes two rings wait for each other). Advisory locks are per database.
     */
    public static function advisoryKey(string $ring): int
    {
        return (self::NAMESPACE << 32) | crc32($ring);
    }

    /**
     * The ring's MySQL lock name. Named locks are server-wide: the database name keeps two
     * applications' rings of the same name apart.
     */
    public static function lockName(Connection $connection, string $ring): string
    {
        return sprintf('sentinel:keys:%u', crc32($connection->getDatabaseName()."\0".$ring));
    }

    /**
     * @template T
     *
     * @param  Closure(): T  $work
     * @return T
     */
    private static function named(Connection $connection, string $ring, Closure $work): mixed
    {
        $name = self::lockName($connection, $ring);
        $row = $connection->selectOne('select get_lock(?, @@innodb_lock_wait_timeout) as acquired', [$name]);

        // 1 = acquired; 0 = timed out; null = an error (e.g. killed while waiting).
        if (! is_object($row) || (int) ($row->acquired ?? 0) !== 1) {
            throw KeyDriverException::ringBusy($ring);
        }

        try {
            return $work();
        } finally {
            $connection->select('select release_lock(?)', [$name]);
        }
    }
}
