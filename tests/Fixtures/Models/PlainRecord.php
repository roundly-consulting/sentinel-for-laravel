<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Models;

use Illuminate\Database\Eloquent\Model;

final class PlainRecord extends Model
{
    protected $table = 'plain_records';

    protected $guarded = [];
}
