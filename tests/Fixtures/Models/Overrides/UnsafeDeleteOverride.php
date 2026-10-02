<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Overrides;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;

/**
 * Overrides delete() and calls the parent directly — the delete would bypass the ledger.
 */
final class UnsafeDeleteOverride extends Model implements Sealable
{
    use HasSeals;

    protected $table = 'plain_records';

    protected $guarded = [];

    public static function defineSeals(SealBuilder $seals): void
    {
        $seals->seal('default')->attributes('name');
    }

    public function delete(): ?bool
    {
        return Model::delete();
    }
}
