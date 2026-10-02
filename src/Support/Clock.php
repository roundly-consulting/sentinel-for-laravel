<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Support\Facades\Date;

/**
 * The only source of "now" in the package (arch-pinned): UTC, microseconds kept, and
 * honouring `Carbon::setTestNow()`. Every stored datetime and every datetime inside a MAC is
 * UTC, whatever `app.timezone` says.
 */
final class Clock
{
    public static function now(): CarbonImmutable
    {
        return Date::now()->toImmutable()->utc();
    }

    /**
     * The canonical-document form: `2026-10-02T18:30:00.000000Z`.
     */
    public static function iso(CarbonInterface $at): string
    {
        return CarbonImmutable::instance($at)->utc()->format('Y-m-d\TH:i:s.u\Z');
    }

    /**
     * The storage / query-binding form: `2026-10-02 18:30:00.000000` (UTC).
     */
    public static function database(CarbonInterface $at): string
    {
        return CarbonImmutable::instance($at)->utc()->format('Y-m-d H:i:s.u');
    }
}
