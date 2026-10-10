<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

/**
 * One of Sentinel's tables, on the connection it lives on (null = the default one).
 *
 * @internal
 */
final readonly class StorageTable
{
    public function __construct(
        public ?string $connection,
        public string $table,
    ) {}

    /**
     * Every table the configuration needs, on its connection: `sentinel_keys` while a ring
     * keeps keys in the database, the idempotency and nonce tables while those stores are the
     * database, and `sentinel_seals` (+ the ledger and its checkpoints while the ledger is on)
     * on every ledger connection. Read by `sentinel:check` and by the upkeep schedule.
     *
     * @return list<self>
     */
    public static function needed(): array
    {
        $needed = [];
        $keyConnection = Settings::keyConnection();

        if (array_filter(Settings::rings(), self::keptInDatabase(...)) !== []) {
            $needed[] = new self($keyConnection, 'sentinel_keys');
        }

        if (Settings::idempotencyStore() === 'database') {
            $needed[] = new self($keyConnection, 'sentinel_idempotency_keys');
        }

        if (Settings::nonceStore() === 'database') {
            $needed[] = new self($keyConnection, 'sentinel_nonces');
        }

        foreach (Settings::ledgerConnections() as $connection) {
            $needed[] = new self($connection, 'sentinel_seals');

            if (Settings::ledgerEnabled()) {
                $needed[] = new self($connection, 'sentinel_ledger');
                $needed[] = new self($connection, 'sentinel_checkpoints');
            }
        }

        return $needed;
    }

    private static function keptInDatabase(string $ring): bool
    {
        $config = Settings::ring($ring);

        return $config->driver === 'database' || ($config->driver === 'chain' && in_array('database', $config->drivers, true));
    }
}
