<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Casts;

use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Every Sentinel datetime column: stored as `Y-m-d H:i:s.u` in UTC and read back as a UTC
 * `CarbonImmutable`, whatever `app.timezone` or the connection's session zone is. A string
 * written to the attribute is taken as UTC (the storage form, optionally ISO with `T`/`Z`).
 *
 * @implements CastsAttributes<CarbonImmutable|null, DateTimeInterface|string|null>
 */
final class UtcDateTime implements CastsAttributes
{
    /**
     * Always read through get(): Laravel would otherwise hand back the (possibly mutable,
     * non-UTC) object that was assigned.
     */
    public bool $withoutObjectCaching = true;

    private const string FORMAT = '/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?Z?$/D';

    /**
     * @param  array<string, mixed>  $attributes
     */
    public function get(Model $model, string $key, mixed $value, array $attributes): ?CarbonImmutable
    {
        return $value === null ? null : self::parse($key, $value);
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        return $value === null ? null : Clock::database(self::parse($key, $value));
    }

    private static function parse(string $key, mixed $value): CarbonImmutable
    {
        if ($value instanceof DateTimeInterface) {
            return CarbonImmutable::instance($value)->utc();
        }

        if (! is_string($value) || preg_match(self::FORMAT, $value, $m) !== 1) {
            throw CorruptRecordException::invalidDatetime($key);
        }

        [$year, $month, $day] = array_map(intval(...), explode('-', $m[1]));
        [$hour, $minute, $second] = array_map(intval(...), explode(':', $m[2]));

        // Well-shaped is not enough: 2026-13-45 99:99:99 must fail closed, not overflow.
        if (! checkdate($month, $day, $year) || $hour > 23 || $minute > 59 || $second > 59) {
            throw CorruptRecordException::invalidDatetime($key);
        }

        return new CarbonImmutable($m[1].' '.$m[2].'.'.str_pad($m[3] ?? '', 6, '0'), 'UTC');
    }
}
