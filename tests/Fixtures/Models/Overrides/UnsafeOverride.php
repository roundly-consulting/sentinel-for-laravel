<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Overrides;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;

/**
 * Overrides save() and calls the parent directly — writes would bypass sealing.
 */
final class UnsafeOverride extends Model implements Sealable
{
    use HasSeals;

    protected $table = 'plain_records';

    protected $guarded = [];

    public static function defineSeals(SealBuilder $seals): void
    {
        $seals->seal('default')->attributes('name');
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public function save(array $options = []): bool
    {
        return Model::save($options);
    }
}
