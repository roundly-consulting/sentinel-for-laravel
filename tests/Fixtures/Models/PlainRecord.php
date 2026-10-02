<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Models;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;

/**
 * No soft deletes, no casts on most columns (runtime `auto` tags), a declared float.
 *
 * @property int $id
 * @property string|null $name
 * @property int|null $count
 */
final class PlainRecord extends Model implements Sealable
{
    use HasSeals;

    protected $table = 'plain_records';

    protected $guarded = [];

    public static function defineSeals(SealBuilder $seals): void
    {
        $seals->seal('default')
            ->attributes('name', 'count', 'code')
            ->boolean('flag')
            ->float('ratio', 3)
            ->datetime('happened_at');
    }
}
