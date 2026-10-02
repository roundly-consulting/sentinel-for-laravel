<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

/**
 * The plain names behind changed field tags: `a:amount` is the column `amount`, `c:lines` the
 * computed field `lines`. Null (unknown — an asymmetric seal stores no tags) reads as none.
 *
 * @internal
 */
final class ChangedFields
{
    /**
     * @param  list<string>|null  $changed
     * @return list<string>
     */
    public static function columns(?array $changed): array
    {
        return self::named($changed, 'a:');
    }

    /**
     * @param  list<string>|null  $changed
     * @return list<string>
     */
    public static function computed(?array $changed): array
    {
        return self::named($changed, 'c:');
    }

    /**
     * @param  list<string>|null  $changed
     * @return list<string>
     */
    private static function named(?array $changed, string $prefix): array
    {
        $names = [];

        foreach ($changed ?? [] as $name) {
            if (str_starts_with($name, $prefix)) {
                $names[] = substr($name, strlen($prefix));
            }
        }

        return $names;
    }
}
