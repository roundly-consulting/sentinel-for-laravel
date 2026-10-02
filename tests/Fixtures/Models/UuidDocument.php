<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;

/**
 * @property string $id
 * @property string $title
 */
final class UuidDocument extends Model implements Sealable
{
    use HasSeals;
    use HasUuids;

    protected $table = 'uuid_documents';

    protected $guarded = [];

    public static function defineSeals(SealBuilder $seals): void
    {
        $seals->seal('content')->attributes('title');
    }
}
