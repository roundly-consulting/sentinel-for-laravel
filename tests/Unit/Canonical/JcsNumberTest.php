<?php

declare(strict_types=1);

use Random\Engine\Mt19937;
use Random\Randomizer;
use RoundlyConsulting\Sentinel\Canonical\JcsNumber;
use RoundlyConsulting\Sentinel\Exceptions\CanonicalizationException;

/**
 * RFC 8785 Appendix B — IEEE-754 bit patterns → ECMAScript Number::toString. The expected
 * strings were re-derived with node's `String(double)` on 2026-10-02.
 */
it('formats the RFC 8785 Appendix B samples', function (string $hex, string $expected): void {
    $value = unpack('E', (string) hex2bin($hex))[1];

    expect(JcsNumber::format($value))->toBe($expected);
})->with([
    ['0000000000000000', '0'],
    ['8000000000000000', '0'],
    ['0000000000000001', '5e-324'],
    ['8000000000000001', '-5e-324'],
    ['7fefffffffffffff', '1.7976931348623157e+308'],
    ['ffefffffffffffff', '-1.7976931348623157e+308'],
    ['4340000000000000', '9007199254740992'],
    ['c340000000000000', '-9007199254740992'],
    ['4430000000000000', '295147905179352830000'],
    ['44b52d02c7e14af5', '9.999999999999997e+22'],
    ['44b52d02c7e14af6', '1e+23'],
    ['44b52d02c7e14af7', '1.0000000000000001e+23'],
    ['444b1ae4d6e2ef4e', '999999999999999700000'],
    ['444b1ae4d6e2ef4f', '999999999999999900000'],
    ['444b1ae4d6e2ef50', '1e+21'],
    ['3eb0c6f7a0b5ed8c', '9.999999999999997e-7'],
    ['3eb0c6f7a0b5ed8d', '0.000001'],
    ['41b3de4355555553', '333333333.3333332'],
    ['41b3de4355555554', '333333333.33333325'],
    ['41b3de4355555555', '333333333.3333333'],
    ['41b3de4355555556', '333333333.3333334'],
    ['41b3de4355555557', '333333333.33333343'],
    ['becbf647612f3696', '-0.0000033333333333333333'],
    ['43143ff3c1cb0959', '1424953923781206.2'],
]);

it('formats the small cases JCS cares about', function (float $value, string $expected): void {
    expect(JcsNumber::format($value))->toBe($expected);
})->with([
    [4.5, '4.5'],
    [2e-3, '0.002'],
    [1e-27, '1e-27'],
    [1e30, '1e+30'],
    [1e-7, '1e-7'],
    [0.000001, '0.000001'],
    [100.0, '100'],
    [-1.5, '-1.5'],
    [0.1, '0.1'],
    [123456789.0, '123456789'],
]);

it('writes the same shortest digits positionally for decimal normalization', function (float $value, string $expected): void {
    expect(JcsNumber::plain($value))->toBe($expected);
})->with([
    [10.5, '10.5'],
    [1e21, '1000000000000000000000'],
    [1e-7, '0.0000001'],
    [-0.0, '0'],
    [0.1 + 0.2, '0.30000000000000004'],
    [-123.25, '-123.25'],
    [5e-324, '0.'.str_repeat('0', 323).'5'],
]);

it('round-trips every formatted double, independently of the precision ini settings', function (): void {
    $precision = ini_get('serialize_precision');
    ini_set('serialize_precision', '5');
    ini_set('precision', '3');

    try {
        $random = new Randomizer(new Mt19937(20261002));

        for ($i = 0; $i < 2000; $i++) {
            $value = unpack('E', $random->getBytes(8))[1];

            if (is_nan($value) || is_infinite($value)) {
                continue;
            }

            expect((float) JcsNumber::format($value))->toBe($value)
                ->and((float) JcsNumber::plain($value))->toBe($value);
        }
    } finally {
        ini_set('serialize_precision', (string) $precision);
        ini_set('precision', '14');
    }
});

it('finds the shortest digits at a power-of-two boundary', function (): void {
    // 2^-1022 and 2^1023 sit on binade edges where the round-trip interval is asymmetric.
    foreach ([2.0 ** -1022, 2.0 ** 1023, 2.0 ** 60, 2.0 ** -60] as $value) {
        expect((float) JcsNumber::format($value))->toBe($value);
    }

    expect(JcsNumber::format(2.0 ** -1022))->toBe('2.2250738585072014e-308')
        ->and(JcsNumber::format(2.0 ** 1023))->toBe('8.98846567431158e+307');
});

it('refuses NaN and infinities', function (float $value): void {
    expect(fn (): string => JcsNumber::format($value))->toThrow(CanonicalizationException::class);
})->with([NAN, INF, -INF]);
