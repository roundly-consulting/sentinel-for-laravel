<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Carbon\CarbonImmutable;

/**
 * A store whose prune can be previewed: how many rows `prune($now)` would delete. The database
 * stores and the fake's in-memory ones implement it, so a dry run reports the same counts
 * under `Sentinel::fake()` as in production; cache stores expire on their own and report 0.
 *
 * @internal
 */
interface CountsExpired
{
    public function countExpired(CarbonImmutable $now): int;
}
