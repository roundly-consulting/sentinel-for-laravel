<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Canonical;

use BackedEnum;
use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Queue\QueueableCollection;
use Illuminate\Contracts\Queue\QueueableEntity;
use JsonException;
use JsonSerializable;
use RoundlyConsulting\Sentinel\Exceptions\CanonicalizationException;
use RoundlyConsulting\Sentinel\Support\Clock;
use stdClass;
use Stringable;

/**
 * RFC 8785 JSON Canonicalization Scheme with exact integers (`sentinel-jcs/1`).
 *
 *  - object members sorted by their UTF-16 code units, no whitespace;
 *  - strings escaped exactly as RFC 8785 §3.2.2.2 (only `"`, `\` and C0 controls);
 *  - doubles as ECMAScript `Number::toString` ({@see JcsNumber});
 *  - **deviation:** a PHP `int` is written as its exact decimal, where JCS would round
 *    integers beyond 2^53 — and a big integer decoded under `JSON_BIGINT_AS_STRING` is a JSON
 *    string (a number and a string of the same digits are therefore equal).
 *
 * PHP lists are arrays, other arrays and `stdClass` are objects; `JsonSerializable`,
 * backed enums, `Stringable` and datetimes (UTC, microseconds) are converted first.
 *
 * @internal
 */
final class Jcs
{
    public const int MAX_DEPTH = 64;

    private const int STRING_FLAGS = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR;

    public static function encode(mixed $value): string
    {
        return self::write($value, 0);
    }

    /**
     * Canonicalize JSON text (a `json` column, a computed JSON string).
     */
    public static function canonicalize(string $json): string
    {
        try {
            $decoded = json_decode($json, false, self::MAX_DEPTH, JSON_BIGINT_AS_STRING | JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw CanonicalizationException::invalidJson();
        }

        return self::write($decoded, 0);
    }

    /**
     * The canonical JSON string literal for a UTF-8 string.
     */
    public static function string(string $value): string
    {
        if (! mb_check_encoding($value, 'UTF-8')) {
            throw CanonicalizationException::invalidUtf8();
        }

        // Valid UTF-8 is guaranteed above, so this cannot fail.
        return json_encode($value, self::STRING_FLAGS);
    }

    private static function write(mixed $value, int $depth): string
    {
        if ($depth > self::MAX_DEPTH) {
            throw CanonicalizationException::invalidJson();
        }

        return match (true) {
            $value === null => 'null',
            $value === true => 'true',
            $value === false => 'false',
            is_int($value) => (string) $value,
            is_float($value) => JcsNumber::format($value),
            is_string($value) => self::string($value),
            is_array($value) => array_is_list($value)
                ? self::writeList($value, $depth)
                : self::writeObject($value, $depth),
            $value instanceof stdClass => self::writeObject(get_object_vars($value), $depth),
            $value instanceof DateTimeInterface => self::string(Clock::iso(CarbonImmutable::instance($value))),
            $value instanceof BackedEnum => self::write($value->value, $depth),
            // A model (or a collection of them) serializes through its own toArray() rules
            // (hidden attributes, appends) — not a stable sealed value. Return keys or arrays.
            $value instanceof QueueableEntity, $value instanceof QueueableCollection => throw CanonicalizationException::computedModel(),
            $value instanceof JsonSerializable => self::write($value->jsonSerialize(), $depth + 1),
            $value instanceof Stringable => self::string((string) $value),
            default => throw CanonicalizationException::unsupportedType(get_debug_type($value)),
        };
    }

    /**
     * @param  list<mixed>  $items
     */
    private static function writeList(array $items, int $depth): string
    {
        $parts = [];

        foreach ($items as $item) {
            $parts[] = self::write($item, $depth + 1);
        }

        return '['.implode(',', $parts).']';
    }

    /**
     * @param  array<array-key, mixed>  $members
     */
    private static function writeObject(array $members, int $depth): string
    {
        $keys = [];

        foreach (array_keys($members) as $key) {
            // PHP turns numeric-string keys into int keys; JSON keys are always strings.
            $key = (string) $key;

            if (! mb_check_encoding($key, 'UTF-8')) {
                throw CanonicalizationException::invalidUtf8();
            }

            $keys[$key] = mb_convert_encoding($key, 'UTF-16BE', 'UTF-8');
        }

        // RFC 8785 §3.2.3: order by UTF-16 code units, compared as unsigned integers —
        // which is exactly a bytewise compare of the big-endian encoding.
        uksort($keys, static fn (string|int $a, string|int $b): int => strcmp($keys[(string) $a], $keys[(string) $b]));

        $parts = [];

        foreach (array_keys($keys) as $key) {
            $parts[] = self::string((string) $key).':'.self::write($members[$key], $depth + 1);
        }

        return '{'.implode(',', $parts).'}';
    }
}
