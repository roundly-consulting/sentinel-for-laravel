<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\StructuredFields;

use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Sentinel\Canonical\JcsNumber;
use RoundlyConsulting\Sentinel\Exceptions\StructuredFieldException;

/**
 * RFC 9651 §4.1 structured field serialization (the canonical form a parser re-reads to the
 * same value). Decimals are rounded half-to-even on their shortest decimal representation.
 *
 * @internal
 *
 * @phpstan-import-type BareItem from Parameters
 */
final class Serializer
{
    private const int MAX_INTEGER = 999_999_999_999_999;

    /**
     * @param  list<Item|InnerList>  $members
     */
    public static function list(array $members): string
    {
        return implode(', ', array_map(self::member(...), $members));
    }

    /**
     * @param  array<string, Item|InnerList>  $members
     */
    public static function dictionary(array $members): string
    {
        $parts = [];

        foreach ($members as $key => $member) {
            $key = (string) $key;

            $parts[] = $member instanceof Item && $member->value === true
                ? self::key($key).self::parameters($member->parameters)
                : self::key($key).'='.self::member($member);
        }

        return implode(', ', $parts);
    }

    public static function item(Item $item): string
    {
        return self::bareItem($item->value).self::parameters($item->parameters);
    }

    public static function innerList(InnerList $list): string
    {
        return '('.implode(' ', array_map(self::item(...), $list->items)).')'.self::parameters($list->parameters);
    }

    public static function parameters(Parameters $parameters): string
    {
        $out = '';

        foreach ($parameters->values as $key => $value) {
            $out .= ';'.self::key((string) $key).($value === true ? '' : '='.self::bareItem($value));
        }

        return $out;
    }

    /**
     * @param  BareItem  $value
     */
    public static function bareItem(int|float|string|bool|Token|ByteSequence|Date|DisplayString $value): string
    {
        return match (true) {
            is_int($value) => self::integer($value),
            is_float($value) => self::decimal($value),
            is_string($value) => self::string($value),
            is_bool($value) => $value ? '?1' : '?0',
            $value instanceof Token => self::token($value->value),
            $value instanceof ByteSequence => ':'.Base64::encode($value->bytes).':',
            $value instanceof Date => '@'.self::integer($value->timestamp),
            $value instanceof DisplayString => self::displayString($value->value),
        };
    }

    private static function member(Item|InnerList $member): string
    {
        return $member instanceof InnerList ? self::innerList($member) : self::item($member);
    }

    private static function key(string $key): string
    {
        if (preg_match('/^[a-z*][a-z0-9_\-.*]*$/D', $key) !== 1) {
            throw StructuredFieldException::serialize("the key [{$key}]");
        }

        return $key;
    }

    private static function integer(int $value): string
    {
        if ($value > self::MAX_INTEGER || $value < -self::MAX_INTEGER) {
            throw StructuredFieldException::serialize('an integer outside ±999,999,999,999,999');
        }

        return (string) $value;
    }

    private static function decimal(float $value): string
    {
        if (! is_finite($value)) {
            throw StructuredFieldException::serialize('a non-finite decimal');
        }

        [$sign, $integer, $fraction] = self::roundHalfEven(JcsNumber::plain($value));

        if (strlen($integer) > 12) {
            throw StructuredFieldException::serialize('a decimal of more than 12 integer digits');
        }

        $fraction = rtrim($fraction, '0');

        return ($integer === '0' && $fraction === '' ? '' : $sign).$integer.'.'.($fraction === '' ? '0' : $fraction);
    }

    /**
     * Round a positional decimal string to three fractional digits, ties to even, exactly.
     *
     * @return array{0: string, 1: string, 2: string} sign, integer digits, three fraction digits
     */
    private static function roundHalfEven(string $plain): array
    {
        $sign = str_starts_with($plain, '-') ? '-' : '';
        [$integer, $fraction] = array_pad(explode('.', ltrim($plain, '-'), 2), 2, '');
        $kept = substr(str_pad($fraction, 3, '0'), 0, 3);
        $rest = substr($fraction, 3);
        $digits = $integer.$kept;

        $roundUp = $rest !== '' && ($rest[0] > '5' || ($rest[0] === '5' && (rtrim(substr($rest, 1), '0') !== '' || ((int) $digits[strlen($digits) - 1]) % 2 === 1)));

        if ($roundUp) {
            $digits = self::increment($digits);
        }

        $integer = ltrim(substr($digits, 0, -3), '0');

        return [$sign, $integer === '' ? '0' : $integer, substr($digits, -3)];
    }

    private static function increment(string $digits): string
    {
        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
            if ($digits[$i] !== '9') {
                return substr($digits, 0, $i).((int) $digits[$i] + 1).str_repeat('0', strlen($digits) - $i - 1);
            }
        }

        return '1'.str_repeat('0', strlen($digits));
    }

    private static function string(string $value): string
    {
        if (preg_match('/[^\x20-\x7E]/', $value) === 1) {
            throw StructuredFieldException::serialize('a string with a character outside printable ASCII');
        }

        return '"'.str_replace(['\\', '"'], ['\\\\', '\\"'], $value).'"';
    }

    private static function token(string $value): string
    {
        if (preg_match("~^[A-Za-z*][!#$%&'*+\-.^_`|\~0-9A-Za-z:/]*$~D", $value) !== 1) {
            throw StructuredFieldException::serialize('an invalid token');
        }

        return $value;
    }

    private static function displayString(string $value): string
    {
        if (! mb_check_encoding($value, 'UTF-8')) {
            throw StructuredFieldException::serialize('a display string that is not UTF-8');
        }

        $out = '%"';

        foreach (str_split($value) as $byte) {
            $ord = ord($byte);
            $out .= $byte === '%' || $byte === '"' || $ord < 0x20 || $ord > 0x7E ? '%'.sprintf('%02x', $ord) : $byte;
        }

        return $out.'"';
    }
}
