<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Models\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Timestamps of Sentinel's own tables: UTC with microseconds. `freshTimestamp()` comes from
 * the package clock (already UTC), so Eloquent's own `created_at`/`updated_at` formatting can
 * never write a local-time string the UTC cast would then misread.
 *
 * @phpstan-require-extends Model
 */
trait StoresUtc
{
    public function freshTimestamp(): Carbon
    {
        return Carbon::instance(Clock::now());
    }

    public function getDateFormat(): string
    {
        return 'Y-m-d H:i:s.u';
    }

    /**
     * No Eloquent date handling at all: the UtcDateTime cast owns every datetime column,
     * timestamps included, so nothing formats them in the app's zone first.
     *
     * @return list<string>
     */
    public function getDates(): array
    {
        return [];
    }
}
