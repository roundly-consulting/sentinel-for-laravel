<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Overrides;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;

/**
 * A sealable base class a host extends (the trait's save() and delete() are its own).
 *
 * @property string|null $name
 */
class SealedBase extends Model implements Sealable
{
    use HasSeals;

    protected $table = 'plain_records';

    protected $guarded = [];

    public static function defineSeals(SealBuilder $seals): void
    {
        $seals->seal('default')->attributes('name');
    }
}
