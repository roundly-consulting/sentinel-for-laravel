<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use RuntimeException;

/**
 * The base of every exception Sentinel throws, so a host can catch the package as a whole.
 */
abstract class SentinelException extends RuntimeException
{
    /**
     * A `sentinel::` translation line (the key itself if it resolves to no string).
     *
     * @param  array<string, string|int>  $replace
     */
    protected static function translated(string $key, array $replace = []): string
    {
        $line = trans("sentinel::{$key}", $replace);

        return is_string($line) ? $line : $key;
    }
}
