<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base32;
use RoundlyConsulting\Sentinel\Exceptions\StructuredFieldException;
use RoundlyConsulting\Sentinel\Http\StructuredFields\ByteSequence;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Date;
use RoundlyConsulting\Sentinel\Http\StructuredFields\DisplayString;
use RoundlyConsulting\Sentinel\Http\StructuredFields\InnerList;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Item;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Parameters;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Parser;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Serializer;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Token;

/**
 * §10 item 53: the httpwg structured-field-tests suite (vendored with its license, see
 * tests/Fixtures/structured-field-tests/SOURCE.md) — every parse and serialisation case.
 * `must_fail` must fail; `can_fail` may go either way, but if it parses it must be right.
 */
function sfCases(string $directory): array
{
    $cases = [];

    foreach (glob(__DIR__.'/../Fixtures/structured-field-tests/'.$directory.'*.json') ?: [] as $file) {
        foreach (json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR) as $case) {
            $cases[basename($file, '.json').': '.$case['name']] = [$case];
        }
    }

    return $cases;
}

/**
 * The suite's JSON data model → this package's value objects.
 */
function sfModel(string $type, mixed $expected): mixed
{
    $bare = static function (mixed $value): mixed {
        if (! is_array($value)) {
            return $value;
        }

        return match ($value['__type']) {
            'token' => new Token($value['value']),
            'binary' => new ByteSequence(Base32::decode($value['value'])),
            'date' => new Date($value['value']),
            'displaystring' => new DisplayString($value['value']),
        };
    };

    $parameters = static function (array $pairs) use ($bare): Parameters {
        $values = [];

        foreach ($pairs as [$key, $value]) {
            $values[$key] = $bare($value);
        }

        return new Parameters($values);
    };

    $item = static fn (array $item): Item => new Item($bare($item[0]), $parameters($item[1]));
    $member = static fn (array $member): Item|InnerList => is_array($member[0]) && array_is_list($member[0])
        ? new InnerList(array_map($item, $member[0]), $parameters($member[1]))
        : $item($member);

    return match ($type) {
        'item' => $item($expected),
        'list' => array_map($member, $expected),
        'dictionary' => array_combine(array_column($expected, 0), array_map(static fn (array $pair): Item|InnerList => $member($pair[1]), $expected)),
    };
}

/**
 * A comparable plain structure of a parsed value (floats by value, bytes as hex).
 */
function sfPlain(mixed $value): mixed
{
    return match (true) {
        $value instanceof Item => ['item', sfPlain($value->value), sfPlain($value->parameters)],
        $value instanceof InnerList => ['inner', array_map(sfPlain(...), $value->items), sfPlain($value->parameters)],
        $value instanceof Parameters => array_map(static fn (string $key): array => [$key, sfPlain($value->values[$key])], array_keys($value->values)),
        $value instanceof Token => ['token', $value->value],
        $value instanceof ByteSequence => ['binary', bin2hex($value->bytes)],
        $value instanceof Date => ['date', $value->timestamp],
        $value instanceof DisplayString => ['display', $value->value],
        is_float($value) => ['number', (string) ($value + 0.0)],
        is_int($value) => ['number', (string) (float) $value],
        is_array($value) => array_map(sfPlain(...), $value),
        default => $value,
    };
}

function sfSerialize(string $type, mixed $model): string
{
    return match ($type) {
        'item' => Serializer::item($model),
        'list' => Serializer::list($model),
        'dictionary' => Serializer::dictionary($model),
    };
}

it('parses the httpwg structured-field-tests suite', function (array $case): void {
    $parse = static fn (): mixed => match ($case['header_type']) {
        'item' => Parser::item($case['raw']),
        'list' => Parser::list($case['raw']),
        'dictionary' => Parser::dictionary($case['raw']),
    };

    if ($case['must_fail'] ?? false) {
        expect($parse)->toThrow(StructuredFieldException::class);

        return;
    }

    try {
        $parsed = $parse();
    } catch (StructuredFieldException $exception) {
        expect($case['can_fail'] ?? false)->toBeTrue("unexpected failure: {$exception->getMessage()}");

        return;
    }

    $canonical = implode(', ', $case['canonical'] ?? $case['raw']);

    expect(sfPlain($parsed))->toEqual(sfPlain(sfModel($case['header_type'], $case['expected'])))
        ->and(sfSerialize($case['header_type'], $parsed))->toBe($canonical);
})->with(sfCases(''));

it('serializes the httpwg serialisation tests', function (array $case): void {
    $serialize = static fn (): string => sfSerialize($case['header_type'], sfModel($case['header_type'], $case['expected']));

    ($case['must_fail'] ?? false)
        ? expect($serialize)->toThrow(StructuredFieldException::class)
        : expect($serialize())->toBe(implode(', ', $case['canonical']));
})->with(sfCases('serialisation-tests/'));

it('refuses values no structured field can hold', function (Closure $serialize): void {
    expect($serialize)->toThrow(StructuredFieldException::class);
})->with([
    'a non-finite decimal' => [static fn (): string => Serializer::bareItem(INF)],
    'a non-UTF-8 display string' => [static fn (): string => Serializer::bareItem(new DisplayString("\xff"))],
    'an invalid token' => [static fn (): string => Serializer::bareItem(new Token('1abc'))],
]);

it('reads and writes parameters', function (): void {
    $parameters = (new Parameters)->with('keyid', 'k')->with('created', 1);

    expect($parameters->get('keyid'))->toBe('k')
        ->and($parameters->has('nonce'))->toBeFalse()
        ->and($parameters->get('nonce'))->toBeNull()
        ->and($parameters->isEmpty())->toBeFalse()
        ->and(Serializer::parameters($parameters))->toBe(';keyid="k";created=1');
});
