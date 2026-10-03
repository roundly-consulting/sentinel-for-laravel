<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Stringable;
use RoundlyConsulting\Sentinel\Canonical\FieldValue;
use RoundlyConsulting\Sentinel\Canonical\JcsNumber;
use RoundlyConsulting\Sentinel\Canonical\Normalizer;
use RoundlyConsulting\Sentinel\Definition\SealType;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\CanonicalizationException;
use RoundlyConsulting\Sentinel\Tests\Fixtures\IntBacked;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;

function canonical(SealType $type, mixed $raw): array
{
    return (new Normalizer)->normalize('a:col', $type, $raw)->tuple();
}

it('keeps the declared tag on null, so null, "", "0", 0 and false are distinct', function (): void {
    expect(canonical(SealType::string(), null))->toBe(['a:col', 'str', null])
        ->and(canonical(SealType::decimal(2), null))->toBe(['a:col', 'dec:2', null])
        ->and(canonical(SealType::auto(), null))->toBe(['a:col', 'null', null])
        ->and(canonical(SealType::plaintext(), null))->toBe(['a:col', 'null', null]);

    $tuples = array_map(static fn (mixed $raw): array => canonical(SealType::auto(), $raw), [null, '', '0', 0, false]);

    expect(array_unique(array_map(serialize(...), $tuples)))->toHaveCount(5);
});

it('normalizes strings and refuses invalid UTF-8', function (): void {
    expect(canonical(SealType::string(), 'Žluť'))->toBe(['a:col', 'str', 'Žluť'])
        ->and(canonical(SealType::string(), new Stringable('s')))->toBe(['a:col', 'str', 's'])
        ->and(canonical(SealType::string(), KeyStatus::Active))->toBe(['a:col', 'str', 'active'])
        ->and(fn () => canonical(SealType::string(), "\xff"))->toThrow(CanonicalizationException::class, 'invalid_utf8')
        ->and(fn () => canonical(SealType::string(), 5))->toThrow(CanonicalizationException::class, 'unsupported_type');
});

it('normalizes integers exactly', function (mixed $raw, string $expected): void {
    expect(canonical(SealType::integer(), $raw))->toBe(['a:col', 'int', $expected]);
})->with([
    [5, '5'],
    [-5, '-5'],
    ['-0', '0'],
    ['+007', '7'],
    ['-007', '-7'],
    ['000', '0'],
    ['123456789012345678901234567890', '123456789012345678901234567890'],
    [IntBacked::Two, '2'],
]);

it('refuses non-integers', function (mixed $raw): void {
    expect(fn () => canonical(SealType::integer(), $raw))->toThrow(CanonicalizationException::class, 'not_integer');
})->with(['1.0', '1e3', ' 1', 1.5, true, 'x', '']);

it('normalizes decimals to a fixed scale from every engine representation', function (mixed $raw, int $scale, string $expected): void {
    expect(canonical(SealType::decimal($scale), $raw))->toBe(['a:col', "dec:{$scale}", $expected]);
})->with([
    'sqlite REAL' => [10.5, 2, '10.50'],
    'mysql string' => ['10.50', 2, '10.50'],
    'pgsql padded' => ['10.500', 2, '10.50'],
    'short string' => ['10.5', 2, '10.50'],
    'integer' => [5, 2, '5.00'],
    'negative zero string' => ['-0.00', 2, '0.00'],
    'negative zero float' => [-0.0, 2, '0.00'],
    'leading zeros' => ['007.10', 2, '7.10'],
    'plus sign' => ['+3.1', 1, '3.1'],
    'scale zero' => ['5', 0, '5'],
    'scale zero trailing zeros' => ['5.000', 0, '5'],
    'negative' => ['-0.0001', 4, '-0.0001'],
    'big' => ['123456789012345678901234567890.12', 2, '123456789012345678901234567890.12'],
]);

it('refuses decimals that do not fit the scale or are not numbers', function (mixed $raw, int $scale): void {
    expect(fn () => canonical(SealType::decimal($scale), $raw))->toThrow(CanonicalizationException::class, 'not_representable');
})->with([
    ['10.505', 2],
    ['5.1', 0],
    [0.1 + 0.2, 2],
    ['1e3', 2],
    ['NaN', 2],
    [NAN, 2],
    [INF, 2],
    [true, 2],
    ['.5', 2],
]);

it('rounds floats half-even to the declared scale', function (mixed $raw, int $scale, string $expected): void {
    expect(canonical(SealType::float($scale), $raw))->toBe(['a:col', "flt:{$scale}", $expected]);
})->with([
    [3.14159, 3, '3.142'],
    [2.5, 0, '2'],
    [3.5, 0, '4'],
    ['2.675', 2, '2.68'],
    ['2.665', 2, '2.66'],
    ['2.6651', 2, '2.67'],
    [-0.4, 0, '0'],
    [-2.5, 0, '-2'],
    [1e-7, 9, '0.000000100'],
    ['1e-7', 9, '0.000000100'],
    ['999.9995', 3, '1000.000'],
    ['.5', 0, '0'],
    ['5.', 1, '5.0'],
    [7, 2, '7.00'],
    ['+1.25', 1, '1.2'],
]);

it('refuses floats that are not finite numbers', function (mixed $raw): void {
    expect(fn () => canonical(SealType::float(2), $raw))->toThrow(CanonicalizationException::class, 'not_representable');
})->with(['abc', 'NaN', 'Infinity', NAN, INF, false, ' 1']);

it('normalizes every boolean representation', function (mixed $raw, string $expected): void {
    expect(canonical(SealType::boolean(), $raw))->toBe(['a:col', 'bool', $expected]);
})->with([
    [true, '1'], [false, '0'], [1, '1'], [0, '0'], ['1', '1'], ['0', '0'],
    ['t', '1'], ['f', '0'], ['T', '1'], ['TRUE', '1'], ['false', '0'],
]);

it('refuses anything else as a boolean', function (mixed $raw): void {
    expect(fn () => canonical(SealType::boolean(), $raw))->toThrow(CanonicalizationException::class, 'not_boolean');
})->with([2, 'yes', 'on', 1.0, '']);

it('takes zone-less datetimes as written, without a zone, and converts offset-bearing ones to UTC (dual-review O-14)', function (mixed $raw, string $expected): void {
    expect(canonical(SealType::datetime(), $raw))->toBe(['a:col', 'dt', $expected]);
})->with([
    'mysql / sqlite' => ['2026-10-02 18:30:00', '2026-10-02T18:30:00.000000'],
    'pgsql trimmed fraction' => ['2026-10-02 18:30:00.5', '2026-10-02T18:30:00.500000'],
    'mysql datetime(6)' => ['2026-10-02 18:30:00.123456', '2026-10-02T18:30:00.123456'],
    'T separator' => ['2026-10-02T18:30:00', '2026-10-02T18:30:00.000000'],
    'Z' => ['2026-10-02 18:30:00Z', '2026-10-02T18:30:00.000000Z'],
    'timestamptz +02' => ['2026-10-02 20:30:00+02', '2026-10-02T18:30:00.000000Z'],
    'timestamptz in New York' => ['2026-10-02 14:30:00.25-04', '2026-10-02T18:30:00.250000Z'],
    'half-hour offset' => ['2026-10-03 00:00:00+05:30', '2026-10-02T18:30:00.000000Z'],
    'LMT seconds offset' => ['1899-12-31 23:59:59+01:39:49', '1899-12-31T22:20:10.000000Z'],
    'crossing midnight' => ['2026-10-02 23:30:00-01:00', '2026-10-03T00:30:00.000000Z'],
    'carbon in another zone' => [CarbonImmutable::parse('2026-10-02 14:30:00', 'America/New_York'), '2026-10-02T18:30:00.000000Z'],
]);

it('is independent of app.timezone', function (): void {
    config()->set('app.timezone', 'Pacific/Kiritimati');
    date_default_timezone_set('Pacific/Kiritimati');

    try {
        expect(canonical(SealType::datetime(), '2026-10-02 18:30:00'))->toBe(['a:col', 'dt', '2026-10-02T18:30:00.000000'])
            ->and(canonical(SealType::datetime(), '2026-10-02 20:30:00+02:00'))->toBe(['a:col', 'dt', '2026-10-02T18:30:00.000000Z']);
    } finally {
        date_default_timezone_set('UTC');
    }
});

it('refuses values that are not datetimes', function (mixed $raw): void {
    expect(fn () => canonical(SealType::datetime(), $raw))->toThrow(CanonicalizationException::class, 'invalid_datetime');
})->with(['2026-13-01 00:00:00', '2026-02-30 00:00:00', '2026-10-02', 'infinity', '2026-10-02 24:00:00', '2026-10-02 18:30:00 BC', '2026-10-02 18:30:60', 12345]);

it('normalizes dates, keeping a time other than midnight as a datetime (dual-review F-5)', function (mixed $raw, string $expected): void {
    expect(canonical(SealType::date(), $raw))->toBe(['a:col', 'date', $expected]);
})->with([
    ['2026-10-02', '2026-10-02'],
    ['2026-10-02 00:00:00', '2026-10-02'],
    ['2026-10-02T00:00:00.000000', '2026-10-02'],
    [CarbonImmutable::parse('2026-10-02 00:00:00', 'Europe/Bratislava'), '2026-10-02'],
    'sqlite keeps the time a date cast wrote' => ['2026-10-02 10:00:00', '2026-10-02T10:00:00.000000'],
    'with a fraction' => ['2026-10-02 10:00:00.25', '2026-10-02T10:00:00.250000'],
    'with an offset' => ['2026-10-02 12:00:00+02:00', '2026-10-02T10:00:00.000000Z'],
]);

it('refuses values that are not dates', function (mixed $raw): void {
    expect(fn () => canonical(SealType::date(), $raw))->toThrow(CanonicalizationException::class, 'invalid_date');
})->with(['2026-02-29', 'x', 20261002, '2026-10-02 24:00:00', '2026-02-30 10:00:00']);

it('never gives a zone-less datetime and a UTC instant the same canonical form (dual-review O-14)', function (SealType $type): void {
    expect(canonical($type, '2026-01-15 10:00:00'))->not->toBe(canonical($type, '2026-01-15T10:00:00Z'))
        ->and(canonical($type, '2026-01-15 10:00:00'))->not->toBe(canonical($type, '2026-01-15 11:00:00+01:00'))
        ->and(canonical($type, '2026-01-15T10:00:00Z'))->toBe(canonical($type, '2026-01-15 11:00:00+01:00'));
})->with([
    'datetime' => [SealType::datetime()],
    'date with a time' => [SealType::date()],
]);

it('canonicalizes JSON text and PHP structures', function (mixed $raw, string $expected): void {
    expect(canonical(SealType::json(), $raw))->toBe(['a:col', 'json', $expected]);
})->with([
    'jsonb reordered' => ['{"b": 1, "a": [1.0, 2]}', '{"a":[1,2],"b":1}'],
    'scalar' => ['5', '5'],
    'array' => [['b' => 1, 'a' => 2], '{"a":2,"b":1}'],
    'list' => [[3, 2.5], '[3,2.5]'],
    'big int' => ['[12345678901234567890123]', '["12345678901234567890123"]'],
]);

it('refuses invalid JSON and models inside JSON', function (): void {
    expect(fn () => canonical(SealType::json(), '{x'))->toThrow(CanonicalizationException::class, 'invalid_json')
        ->and(fn () => canonical(SealType::json(), ['m' => new PlainRecord]))->toThrow(CanonicalizationException::class, 'computed_model');
});

it('base64url-encodes binary strings and streams', function (): void {
    $stream = fopen('php://memory', 'w+b');
    fwrite($stream, "\x00\xff");

    expect(canonical(SealType::binary(), "\x00\xff"))->toBe(['a:col', 'bin', 'AP8'])
        ->and(canonical(SealType::binary(), $stream))->toBe(['a:col', 'bin', 'AP8'])
        ->and(canonical(SealType::binary(), ''))->toBe(['a:col', 'bin', ''])
        ->and(fn () => canonical(SealType::binary(), 5))->toThrow(CanonicalizationException::class, 'unsupported_type');
});

it('types auto and plaintext values by their PHP type', function (SealType $type): void {
    expect(canonical($type, 5))->toBe(['a:col', 'int', '5'])
        ->and(canonical($type, true))->toBe(['a:col', 'bool', '1'])
        ->and(canonical($type, 'x'))->toBe(['a:col', 'str', 'x'])
        ->and(canonical($type, VerificationStatus::Tampered))->toBe(['a:col', 'str', 'tampered'])
        ->and(canonical($type, IntBacked::Two))->toBe(['a:col', 'int', '2'])
        ->and(canonical($type, CarbonImmutable::parse('2026-10-02 20:30:00', 'Europe/Bratislava')))->toBe(['a:col', 'dt', '2026-10-02T18:30:00.000000Z'])
        ->and(canonical($type, ['b' => 1, 'a' => null]))->toBe(['a:col', 'json', '{"a":null,"b":1}'])
        ->and(canonical($type, (object) ['k' => 'v']))->toBe(['a:col', 'json', '{"k":"v"}'])
        ->and(fn () => canonical($type, 1.5))->toThrow(CanonicalizationException::class, 'float_requires_declaration')
        ->and(fn () => canonical($type, new PlainRecord))->toThrow(CanonicalizationException::class, 'computed_model')
        ->and(fn () => canonical($type, fopen('php://memory', 'r')))->toThrow(CanonicalizationException::class, 'unsupported_type');
})->with([
    'auto' => [SealType::auto()],
    'plaintext' => [SealType::plaintext()],
]);

it('types computed values by PHP type unless declared', function (): void {
    $normalizer = new Normalizer;

    expect($normalizer->computed('c:total', 10.5, SealType::decimal(2)))->toEqual(new FieldValue('c:total', 'dec:2', '10.50'))
        ->and($normalizer->computed('c:count', 3))->toEqual(new FieldValue('c:count', 'int', '3'))
        ->and(fn () => $normalizer->computed('c:ratio', 0.5))->toThrow(CanonicalizationException::class, 'Field [c:ratio]');
});

it('names the field and reason, never the value, when it refuses', function (): void {
    try {
        (new Normalizer)->normalize('a:secret_amount', SealType::decimal(2), '123.456789');
        $this->fail('expected an exception');
    } catch (CanonicalizationException $exception) {
        expect($exception->getMessage())->toContain('a:secret_amount')->not->toContain('123.456789')
            ->and($exception->reason())->toBe('not_representable')
            ->and($exception->field())->toBe('a:secret_amount');
    }
});

it('writes a float decimal positionally, never with an exponent, as the spec says (dual-review O-41)', function (): void {
    // canonical-format-v1.md: shortest round-trip digits, positional (JcsNumber::plain()) — an
    // independent verifier using the ECMAScript form (1e-7) would mismatch.
    expect(JcsNumber::plain(1.0E-7))->toBe('0.0000001')
        ->and(canonical(SealType::decimal(7), 1.0E-7))->toBe(['a:col', 'dec:7', '0.0000001'])
        ->and(canonical(SealType::decimal(2), 12345678.5))->toBe(['a:col', 'dec:2', '12345678.50'])
        ->and(method_exists(JcsNumber::class, 'shortest'))->toBeFalse();
});
