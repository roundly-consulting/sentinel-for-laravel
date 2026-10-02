<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Canonical;

use BackedEnum;
use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Queue\QueueableCollection;
use Illuminate\Contracts\Queue\QueueableEntity;
use JsonSerializable;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Sentinel\Definition\SealType;
use RoundlyConsulting\Sentinel\Enums\TypeKind;
use RoundlyConsulting\Sentinel\Exceptions\CanonicalizationException;
use RoundlyConsulting\Sentinel\Support\Clock;
use stdClass;
use Stringable;

/**
 * Raw driver values (and computed PHP values) → canonical field tuples, per declared tag
 * (`sentinel.seal/1`, plan §4.3.2). Deterministic across SQLite, PostgreSQL and MySQL, and
 * independent of `app.timezone` and PHP's float ini settings. Every rule rejects with a
 * {@see CanonicalizationException} rather than guessing.
 *
 * `null` keeps the declared tag (`[name, "str", null]`), so `null`, `""`, `"0"`, `0` and
 * `false` are five distinct tuples. `auto` and `plain` type the value by its PHP type.
 *
 * @internal
 */
final class Normalizer
{
    private const string DATETIME = '/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}(?::?\d{2}(?::?\d{2})?)?)?$/D';

    private const string DATE = '/^(\d{4})-(\d{2})-(\d{2})(?:[ T]00:00:00(?:\.0{1,6})?)?$/D';

    private const string DECIMAL = '/^([+-]?)(\d+)(?:\.(\d+))?$/D';

    private const string FLOAT = '/^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/D';

    public function normalize(string $name, SealType $declared, mixed $raw): FieldValue
    {
        if ($raw === null) {
            $tag = $declared->kind === TypeKind::Auto || $declared->kind === TypeKind::Plaintext
                ? TypeKind::Null->value
                : $declared->tag();

            return new FieldValue($name, $tag, null);
        }

        try {
            return match ($declared->kind) {
                TypeKind::String => new FieldValue($name, 'str', $this->string($raw)),
                TypeKind::Integer => new FieldValue($name, 'int', $this->integer($raw)),
                TypeKind::Decimal => new FieldValue($name, $declared->tag(), $this->decimal($raw, (int) $declared->scale)),
                TypeKind::Float => new FieldValue($name, $declared->tag(), $this->float($raw, (int) $declared->scale)),
                TypeKind::Boolean => new FieldValue($name, 'bool', $this->boolean($raw)),
                TypeKind::DateTime => new FieldValue($name, 'dt', $this->datetime($raw)),
                TypeKind::Date => new FieldValue($name, 'date', $this->date($raw)),
                TypeKind::Json => new FieldValue($name, 'json', $this->json($raw)),
                TypeKind::Binary => new FieldValue($name, 'bin', $this->binary($raw)),
                TypeKind::Auto, TypeKind::Plaintext => $this->byPhpType($name, $raw),
                TypeKind::Null => throw CanonicalizationException::unsupportedType('null'),
            };
        } catch (CanonicalizationException $exception) {
            throw $exception->forField($name);
        }
    }

    /**
     * A computed value: typed by its PHP type unless a type is declared with `$as`.
     */
    public function computed(string $name, mixed $value, ?SealType $as = null): FieldValue
    {
        return $this->normalize($name, $as ?? SealType::auto(), $value);
    }

    private function byPhpType(string $name, mixed $raw): FieldValue
    {
        return match (true) {
            $raw instanceof QueueableEntity, $raw instanceof QueueableCollection => throw CanonicalizationException::computedModel(),
            // Before Stringable: Carbon is Stringable, but a datetime is a `dt`.
            $raw instanceof DateTimeInterface => new FieldValue($name, 'dt', $this->datetime($raw)),
            is_string($raw), $raw instanceof Stringable => new FieldValue($name, 'str', $this->string($raw)),
            is_int($raw) => new FieldValue($name, 'int', (string) $raw),
            is_bool($raw) => new FieldValue($name, 'bool', $raw ? '1' : '0'),
            is_float($raw) => throw CanonicalizationException::floatRequiresDeclaration(),
            $raw instanceof BackedEnum => is_int($raw->value)
                ? new FieldValue($name, 'int', (string) $raw->value)
                : new FieldValue($name, 'str', $this->string($raw->value)),
            is_array($raw), $raw instanceof stdClass, $raw instanceof JsonSerializable => new FieldValue($name, 'json', Jcs::encode($raw)),
            default => throw CanonicalizationException::unsupportedType(get_debug_type($raw)),
        };
    }

    private function string(mixed $raw): string
    {
        $value = match (true) {
            is_string($raw) => $raw,
            $raw instanceof Stringable => (string) $raw,
            $raw instanceof BackedEnum && is_string($raw->value) => $raw->value,
            default => throw CanonicalizationException::unsupportedType(get_debug_type($raw)),
        };

        if (! mb_check_encoding($value, 'UTF-8')) {
            throw CanonicalizationException::invalidUtf8();
        }

        return $value;
    }

    private function integer(mixed $raw): string
    {
        if ($raw instanceof BackedEnum) {
            $raw = $raw->value;
        }

        if (is_int($raw)) {
            return (string) $raw;
        }

        if (! is_string($raw) || preg_match('/^([+-]?)(\d+)$/D', $raw, $m) !== 1) {
            throw CanonicalizationException::notInteger();
        }

        $digits = ltrim($m[2], '0');

        if ($digits === '') {
            return '0';
        }

        return ($m[1] === '-' ? '-' : '').$digits;
    }

    private function decimal(mixed $raw, int $scale): string
    {
        $text = match (true) {
            is_int($raw) => (string) $raw,
            is_float($raw) => $this->finitePlain($raw),
            is_string($raw) => $raw,
            default => throw CanonicalizationException::notRepresentable(),
        };

        if (preg_match(self::DECIMAL, $text, $m) !== 1) {
            throw CanonicalizationException::notRepresentable();
        }

        $fraction = $m[3] ?? '';

        if (strlen($fraction) > $scale) {
            if (trim(substr($fraction, $scale), '0') !== '') {
                throw CanonicalizationException::notRepresentable();
            }

            $fraction = substr($fraction, 0, $scale);
        }

        return $this->assemble($m[1] === '-', $m[2], str_pad($fraction, $scale, '0'), $scale);
    }

    private function float(mixed $raw, int $scale): string
    {
        $text = match (true) {
            is_int($raw) => (string) $raw,
            is_float($raw) => $this->finitePlain($raw),
            is_string($raw) && preg_match(self::FLOAT, $raw) === 1 => preg_match('/[eE]/', $raw) === 1
                ? $this->finitePlain((float) $raw)
                : $raw,
            default => throw CanonicalizationException::notRepresentable(),
        };

        // ".5" / "5." / "+5" → sign, integer part, fraction part.
        preg_match('/^([+-]?)(\d*)(?:\.(\d*))?$/D', $text, $m);

        return $this->roundHalfEven(($m[1] ?? '') === '-', ($m[2] ?? '') === '' ? '0' : $m[2], $m[3] ?? '', $scale);
    }

    private function roundHalfEven(bool $negative, string $integer, string $fraction, int $scale): string
    {
        if (strlen($fraction) <= $scale) {
            return $this->assemble($negative, $integer, str_pad($fraction, $scale, '0'), $scale);
        }

        $kept = substr($fraction, 0, $scale);
        $first = (int) $fraction[$scale];
        $tail = trim(substr($fraction, $scale + 1), '0');
        $last = (int) substr($integer.$kept, -1);

        $up = $first > 5 || ($first === 5 && ($tail !== '' || $last % 2 === 1));

        $digits = $integer.$kept;

        if ($up) {
            $digits = $this->increment($digits);
        }

        $integerLength = strlen($digits) - $scale;

        return $this->assemble($negative, substr($digits, 0, $integerLength), substr($digits, $integerLength), $scale);
    }

    private function increment(string $digits): string
    {
        $i = strlen($digits) - 1;

        while ($i >= 0) {
            if ($digits[$i] !== '9') {
                $digits[$i] = (string) ((int) $digits[$i] + 1);

                return $digits;
            }

            $digits[$i] = '0';
            $i--;
        }

        return '1'.$digits;
    }

    private function assemble(bool $negative, string $integer, string $fraction, int $scale): string
    {
        $integer = ltrim($integer, '0');
        $integer = $integer === '' ? '0' : $integer;
        $body = $scale === 0 ? $integer : $integer.'.'.$fraction;

        // -0, -0.00 → 0, 0.00
        $isZero = trim($integer.$fraction, '0') === '';

        return ($negative && ! $isZero ? '-' : '').$body;
    }

    private function finitePlain(float $value): string
    {
        if (is_nan($value) || is_infinite($value)) {
            throw CanonicalizationException::notRepresentable();
        }

        return JcsNumber::plain($value);
    }

    private function boolean(mixed $raw): string
    {
        if (is_bool($raw)) {
            return $raw ? '1' : '0';
        }

        if ($raw === 1 || $raw === 0) {
            return (string) $raw;
        }

        if (is_string($raw)) {
            return match (strtolower($raw)) {
                '1', 't', 'true' => '1',
                '0', 'f', 'false' => '0',
                default => throw CanonicalizationException::notBoolean(),
            };
        }

        throw CanonicalizationException::notBoolean();
    }

    private function datetime(mixed $raw): string
    {
        if ($raw instanceof DateTimeInterface) {
            return Clock::iso(CarbonImmutable::instance($raw));
        }

        if (! is_string($raw) || preg_match(self::DATETIME, $raw, $m) !== 1) {
            throw CanonicalizationException::invalidDatetime();
        }

        [, $year, $month, $day, $hour, $minute, $second] = $m;
        $fraction = str_pad($m[7] ?? '', 6, '0');
        $offset = $m[8] ?? '';

        if (! checkdate((int) $month, (int) $day, (int) $year) || (int) $hour > 23 || (int) $minute > 59 || (int) $second > 59) {
            throw CanonicalizationException::invalidDatetime();
        }

        $written = "{$year}-{$month}-{$day}T{$hour}:{$minute}:{$second}.{$fraction}Z";

        // A zone-less value is taken as written (no shift — app.timezone never leaks in);
        // an offset-bearing value (pgsql timestamptz in any session zone) becomes UTC.
        if ($offset === '' || $offset === 'Z') {
            return $written;
        }

        $parts = str_split(str_replace(':', '', substr($offset, 1)), 2);
        $seconds = ((int) $parts[0]) * 3600 + ((int) ($parts[1] ?? 0)) * 60 + (int) ($parts[2] ?? 0);

        $local = new CarbonImmutable("{$year}-{$month}-{$day} {$hour}:{$minute}:{$second}.{$fraction}", 'UTC');

        return Clock::iso($offset[0] === '+' ? $local->subSeconds($seconds) : $local->addSeconds($seconds));
    }

    private function date(mixed $raw): string
    {
        if ($raw instanceof DateTimeInterface) {
            // The calendar date in the value's own zone: converting a local midnight to UTC
            // would move it to the previous day.
            return $raw->format('Y-m-d');
        }

        if (! is_string($raw) || preg_match(self::DATE, $raw, $m) !== 1 || ! checkdate((int) $m[2], (int) $m[3], (int) $m[1])) {
            throw CanonicalizationException::invalidDate();
        }

        return "{$m[1]}-{$m[2]}-{$m[3]}";
    }

    private function json(mixed $raw): string
    {
        return is_string($raw) ? Jcs::canonicalize($raw) : Jcs::encode($raw);
    }

    private function binary(mixed $raw): string
    {
        if (is_resource($raw)) {
            $contents = stream_get_contents($raw, offset: 0);

            return Base64Url::encode(is_string($contents) ? $contents : throw CanonicalizationException::unsupportedType('resource'));
        }

        if (! is_string($raw)) {
            throw CanonicalizationException::unsupportedType(get_debug_type($raw));
        }

        return Base64Url::encode($raw);
    }
}
