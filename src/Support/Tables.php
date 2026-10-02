<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Models\Seal;

/**
 * Seal and ledger rows always live on the sealable's own connection, so they commit or roll
 * back with the model write they describe. Every engine query goes through here.
 */
final class Tables
{
    public static function seal(Model $sealable): Seal
    {
        return (new Seal)->setConnection($sealable->getConnectionName());
    }

    public static function ledger(Model $sealable): LedgerEntry
    {
        return (new LedgerEntry)->setConnection($sealable->getConnectionName());
    }

    /**
     * @return Builder<Seal>
     */
    public static function seals(Model $sealable, string $seal): Builder
    {
        return self::seal($sealable)->newQuery()
            ->where('sealable_type', $sealable->getMorphClass())
            ->where('sealable_id', $sealable->getKey())
            ->where('seal', $seal);
    }

    /**
     * @return Builder<LedgerEntry>
     */
    public static function entries(Model $sealable, string $seal): Builder
    {
        return self::ledger($sealable)->newQuery()
            ->where('sealable_type', $sealable->getMorphClass())
            ->where('sealable_id', $sealable->getKey())
            ->where('seal', $seal);
    }

    /**
     * The checkpoints of a connection (null = the default one).
     *
     * @return Builder<Checkpoint>
     */
    public static function checkpoints(?string $connection): Builder
    {
        return (new Checkpoint)->setConnection($connection)->newQuery();
    }

    public static function checkpoint(?string $connection): Checkpoint
    {
        return (new Checkpoint)->setConnection($connection);
    }

    /**
     * Every ledger entry of a connection (null = the default one).
     *
     * @return Builder<LedgerEntry>
     */
    public static function ledgerOn(?string $connection): Builder
    {
        return (new LedgerEntry)->setConnection($connection)->newQuery();
    }

    /**
     * Every seal row of a connection (null = the default one).
     *
     * @return Builder<Seal>
     */
    public static function sealsOn(?string $connection): Builder
    {
        return (new Seal)->setConnection($connection)->newQuery();
    }

    /**
     * The name of a connection (null = the default one).
     */
    public static function connectionName(?string $connection): string
    {
        return (new Checkpoint)->setConnection($connection)->getConnection()->getName() ?? 'default';
    }
}
