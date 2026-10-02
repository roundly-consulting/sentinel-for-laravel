<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
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
}
