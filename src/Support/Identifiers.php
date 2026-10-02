<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

/**
 * The identifier grammars Sentinel accepts. Identifiers end up inside MACs, HKDF info strings
 * (NUL-separated) and log lines, so they are strict allow-lists: no NUL, no whitespace, no
 * trailing newline (every pattern is anchored with `D`).
 */
final class Identifiers
{
    public const string RING = '/^[a-z][a-z0-9_-]{0,63}$/D';

    public const string KEY_ID = '/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/D';

    public const string SEAL = '/^[a-z][a-z0-9_.-]{0,63}$/D';

    public const string COLUMN = '/^[A-Za-z_][A-Za-z0-9_]{0,63}$/D';

    public const string COMPUTED = '/^[a-z][a-z0-9_]{0,63}$/D';

    public const string PURPOSE = '/^[a-z0-9][a-z0-9:._-]{0,127}$/D';

    public static function isRing(string $value): bool
    {
        return preg_match(self::RING, $value) === 1;
    }

    public static function isKeyId(string $value): bool
    {
        return preg_match(self::KEY_ID, $value) === 1;
    }

    public static function isSeal(string $value): bool
    {
        return preg_match(self::SEAL, $value) === 1;
    }

    public static function isColumn(string $value): bool
    {
        return preg_match(self::COLUMN, $value) === 1;
    }

    public static function isComputed(string $value): bool
    {
        return preg_match(self::COMPUTED, $value) === 1;
    }

    public static function isPurpose(string $value): bool
    {
        return preg_match(self::PURPOSE, $value) === 1;
    }

    /**
     * A comma-separated env list: trimmed, empties dropped, order kept.
     *
     * @return list<string>
     */
    public static function csv(mixed $value): array
    {
        if (! is_string($value)) {
            return [];
        }

        return array_values(array_filter(
            array_map(trim(...), explode(',', $value)),
            static fn (string $item): bool => $item !== '',
        ));
    }
}
