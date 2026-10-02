<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * A model whose table never exists — every query against it throws.
 */
final class ThrowingOwner extends Model
{
    protected $table = 'sentinel_fixture_missing_table';
}
