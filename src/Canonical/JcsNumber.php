<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Canonical;

use RoundlyConsulting\Sentinel\Exceptions\CanonicalizationException;

/**
 * IEEE-754 doubles as RFC 8785 serializes them: ECMAScript `Number::toString` (ECMA-262
 * §6.1.6.1.20) — the shortest round-tripping digits, closest to the value.
 *
 * Independent of the `precision` / `serialize_precision` ini settings: digits come from
 * `sprintf('%.Ne')` (correctly rounded) and are proven by a round-trip parse.
 *
 * @internal
 */
final class JcsNumber
{
    /**
     * The ECMAScript string form (`1e+21`, `0.000001`, `333333333.3333332`, `5e-324`).
     */
    public static function format(float $value): string
    {
        $exponent = 0;
        $sign = '';
        $digits = self::digits($value, $exponent, $sign);

        if ($digits === '0') {
            return '0';
        }

        $k = strlen($digits);
        $n = $exponent;

        $body = match (true) {
            $k <= $n && $n <= 21 => $digits.str_repeat('0', $n - $k),
            $n > 0 && $n <= 21 => substr($digits, 0, $n).'.'.substr($digits, $n),
            $n > -6 && $n <= 0 => '0.'.str_repeat('0', -$n).$digits,
            default => $digits[0].($k > 1 ? '.'.substr($digits, 1) : '').'e'.($n - 1 >= 0 ? '+' : '-').abs($n - 1),
        };

        return $sign.$body;
    }

    /**
     * The same shortest digits, written positionally (never an exponent) — how a float
     * read from a database (SQLite REAL) enters decimal normalization.
     */
    public static function plain(float $value): string
    {
        $exponent = 0;
        $sign = '';
        $digits = self::digits($value, $exponent, $sign);

        if ($digits === '0') {
            return '0';
        }

        $k = strlen($digits);
        $n = $exponent;

        $body = match (true) {
            $n >= $k => $digits.str_repeat('0', $n - $k),
            $n > 0 => substr($digits, 0, $n).'.'.substr($digits, $n),
            default => '0.'.str_repeat('0', -$n).$digits,
        };

        return $sign.$body;
    }

    /**
     * The shortest significant digits of |value| (no leading/trailing zeros) and, through
     * $exponent, the ECMAScript `n` such that value = 0.digits × 10^n.
     */
    private static function digits(float $value, int &$exponent, string &$sign): string
    {
        if (is_nan($value) || is_infinite($value)) {
            throw CanonicalizationException::notRepresentable();
        }

        if ($value == 0.0) {
            $exponent = 0;
            $sign = '';

            return '0';
        }

        $sign = $value < 0 ? '-' : '';
        $x = abs($value);

        for ($precision = 1; $precision < 17; $precision++) {
            [$coefficient, $power] = explode('e', sprintf('%.'.($precision - 1).'e', $x));
            $mantissa = str_replace('.', '', $coefficient);
            $power = (int) $power - ($precision - 1);

            // The correctly rounded candidate first, then its neighbours: at a power-of-two
            // boundary the round-trip interval is asymmetric, so the nearest p-digit value
            // can miss while the next one up still parses back to x.
            foreach ([$mantissa, self::step($mantissa, 1), self::step($mantissa, -1)] as $candidate) {
                if ($candidate !== null && (float) ($candidate.'e'.$power) === $x) {
                    return self::significant($candidate, $power, $exponent);
                }
            }
        }

        // 17 significant digits always round-trip a double.
        [$coefficient, $power] = explode('e', sprintf('%.16e', $x));

        return self::significant(str_replace('.', '', $coefficient), (int) $power - 16, $exponent);
    }

    private static function significant(string $mantissa, int $power, int &$exponent): string
    {
        $significant = ltrim($mantissa, '0');
        $exponent = strlen($significant) + $power;

        return rtrim($significant, '0');
    }

    /**
     * The decimal integer string plus or minus one, or null when it would leave the
     * positive range.
     */
    private static function step(string $integer, int $delta): ?string
    {
        $digits = str_split($integer);
        $i = count($digits) - 1;

        while ($i >= 0) {
            $digit = (int) $digits[$i] + $delta;

            if ($digit >= 0 && $digit <= 9) {
                $digits[$i] = (string) $digit;

                return ltrim(implode('', $digits), '0') ?: null;
            }

            $digits[$i] = $delta > 0 ? '0' : '9';
            $i--;
        }

        return $delta > 0 ? '1'.implode('', $digits) : null;
    }
}
