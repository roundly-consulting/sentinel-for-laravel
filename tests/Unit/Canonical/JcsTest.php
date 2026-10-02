<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Collection;
use Illuminate\Support\Stringable;
use RoundlyConsulting\Sentinel\Canonical\Jcs;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\CanonicalizationException;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;

/**
 * JSON escapes are assembled from chr(92) so the RFC text survives any tooling that would
 * decode a literal backslash-u sequence.
 */
function u(string $hex): string
{
    return chr(92).'u'.$hex;
}

it('canonicalizes the RFC 8785 §3.2.2 sample', function (): void {
    $bs = chr(92);
    $input = '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], '
        .'"string": "'.u('20ac').'$'.u('000F').u('000a')."A'".u('0042').u('0022').u('005c').$bs.$bs.$bs.'"'.$bs.'/", '
        .'"literals": [null, true, false]}';

    $expected = '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"'
        ."\u{20AC}$".u('000f').$bs.'n'."A'B".$bs.'"'.$bs.$bs.$bs.$bs.$bs.'"/"}';

    expect(Jcs::canonicalize($input))->toBe($expected);
});

it('sorts members by UTF-16 code units (RFC 8785 §3.2.3)', function (): void {
    $input = '{"'.u('20ac').'":"Euro Sign","'.chr(92).'r":"Carriage Return","'.u('fb33').'":"Hebrew Letter Dalet With Dagesh",'
        .'"1":"One","'.u('d83d').u('de00').'":"Emoji: Grinning Face","'.u('0080').'":"Control",'
        .'"'.u('00f6').'":"Latin Small Letter O With Diaeresis"}';

    $values = array_values((array) json_decode(Jcs::canonicalize($input), false, 4, JSON_THROW_ON_ERROR));

    expect($values)->toBe([
        'Carriage Return', 'One', 'Control', 'Latin Small Letter O With Diaeresis',
        'Euro Sign', 'Emoji: Grinning Face', 'Hebrew Letter Dalet With Dagesh',
    ]);
});

it('escapes only quotes, backslashes and C0 controls, never U+2028 or slashes', function (): void {
    expect(Jcs::string("a\u{2028}b\u{2029}/\x7f\x1f\x08"))->toBe("\"a\u{2028}b\u{2029}/\x7f\\u001f\\b\"");
});

it('writes PHP ints exactly, beyond 2^53 (the sentinel-jcs/1 deviation)', function (): void {
    expect(Jcs::encode([PHP_INT_MAX, -PHP_INT_MAX - 1, 9007199254740993]))
        ->toBe('[9223372036854775807,-9223372036854775808,9007199254740993]');
});

it('keeps big JSON integers exact as strings', function (): void {
    expect(Jcs::canonicalize('{"n":123456789012345678901234567890}'))->toBe('{"n":"123456789012345678901234567890"}');
});

it('distinguishes empty objects from empty arrays', function (): void {
    expect(Jcs::canonicalize('{"a":{},"b":[]}'))->toBe('{"a":{},"b":[]}')
        ->and(Jcs::encode(new stdClass))->toBe('{}')
        ->and(Jcs::encode([]))->toBe('[]');
});

it('turns numeric-string keys back into JSON string keys', function (): void {
    expect(Jcs::canonicalize('{"10":"b","9":"a"}'))->toBe('{"10":"b","9":"a"}')
        ->and(Jcs::encode([2 => 'x', 1 => 'y']))->toBe('{"1":"y","2":"x"}');
});

it('converts serializable, enum, stringable and datetime values', function (): void {
    $value = [
        'collection' => new Collection(['b' => 1, 'a' => 2]),
        'enum' => Algorithm::Ed25519,
        'stringable' => new Stringable('text'),
        'at' => CarbonImmutable::parse('2026-10-02 20:30:00.25', 'Europe/Bratislava'),
        'float' => 1.0,
    ];

    expect(Jcs::encode($value))
        ->toBe('{"at":"2026-10-02T18:30:00.250000Z","collection":{"a":2,"b":1},"enum":"ed25519","float":1,"stringable":"text"}');
});

it('rejects invalid UTF-8 in values and keys', function (mixed $value): void {
    expect(fn (): string => Jcs::encode($value))->toThrow(CanonicalizationException::class, 'invalid_utf8');
})->with([
    "\xff",
    [["\xc3\x28"]],
    [["\xff" => 1]],
]);

it('rejects invalid JSON text and nesting deeper than 64', function (string $json): void {
    expect(fn (): string => Jcs::canonicalize($json))->toThrow(CanonicalizationException::class, 'invalid_json');
})->with([
    'not json' => ['{"a":'],
    'too deep' => [str_repeat('[', 65).str_repeat(']', 65)],
]);

it('rejects PHP values nested deeper than 64', function (): void {
    $value = [];

    for ($i = 0; $i < 70; $i++) {
        $value = [$value];
    }

    expect(fn (): string => Jcs::encode($value))->toThrow(CanonicalizationException::class, 'invalid_json');
});

it('rejects models, resources and arbitrary objects', function (): void {
    expect(fn (): string => Jcs::encode([new PlainRecord]))->toThrow(CanonicalizationException::class, 'computed_model')
        ->and(fn (): string => Jcs::encode([fopen('php://memory', 'r')]))->toThrow(CanonicalizationException::class, 'unsupported_type')
        ->and(fn (): string => Jcs::encode([new ArrayObject]))->toThrow(CanonicalizationException::class, 'unsupported_type');
});
