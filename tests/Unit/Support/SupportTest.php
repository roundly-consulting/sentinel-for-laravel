<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use RoundlyConsulting\Sentinel\Definition\SealType;
use RoundlyConsulting\Sentinel\Enums\TypeKind;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSealDefinitionException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Identifiers;
use RoundlyConsulting\Sentinel\Support\Settings;

it('reads now in UTC with microseconds and honours the test clock', function (): void {
    Carbon::setTestNow(CarbonImmutable::parse('2026-10-02 20:30:00.654321', 'Europe/Bratislava'));

    try {
        $now = Clock::now();

        expect($now)->toBeInstanceOf(CarbonImmutable::class)
            ->and($now->getTimezone()->getName())->toBe('UTC')
            ->and(Clock::iso($now))->toBe('2026-10-02T18:30:00.654321Z')
            ->and(Clock::database($now))->toBe('2026-10-02 18:30:00.654321');
    } finally {
        Carbon::setTestNow();
    }
});

it('accepts only identifiers of the documented grammars', function (string $method, string $value, bool $valid): void {
    expect(Identifiers::{$method}($value))->toBe($valid);
})->with([
    ['isRing', 'default', true], ['isRing', 'http-partners_2', true], ['isRing', 'Default', false], ['isRing', "default\n", false], ['isRing', str_repeat('a', 65), false],
    ['isKeyId', 'default-20261002-k3f9qa', true], ['isKeyId', 'A.b_c-1', true], ['isKeyId', '-x', false], ['isKeyId', "k\0", false], ['isKeyId', 'k id', false],
    ['isSeal', 'financial', true], ['isSeal', 'v1.identity', true], ['isSeal', '1st', false],
    ['isColumn', 'customer_id', true], ['isColumn', '_private', true], ['isColumn', 'a-b', false], ['isColumn', 'a.b', false],
    ['isComputed', 'line_total', true], ['isComputed', 'LineTotal', false],
    ['isPurpose', 'url:exports.download', true], ['isPurpose', 'Login', false],
]);

it('parses comma-separated env lists', function (mixed $value, array $expected): void {
    expect(Identifiers::csv($value))->toBe($expected);
})->with([
    [' a, b ,,c ', ['a', 'b', 'c']],
    ['', []],
    [null, []],
    [['a'], []],
]);

it('validates the context and defaults it to empty', function (): void {
    config()->set('sentinel.context', null);
    expect(Settings::context())->toBe('');

    config()->set('sentinel.context', 'billing-eu');
    expect(Settings::context())->toBe('billing-eu');

    foreach ([str_repeat('x', 256), "\xff", 5] as $invalid) {
        config()->set('sentinel.context', $invalid);
        expect(fn () => Settings::context())->toThrow(InvalidSentinelConfigurationException::class, 'sentinel.context');
    }
});

it('builds declared types and parses stored tags strictly', function (): void {
    expect(SealType::decimal(2)->tag())->toBe('dec:2')
        ->and(SealType::float(0)->tag())->toBe('flt:0')
        ->and(SealType::json()->tag())->toBe('json')
        ->and(SealType::plaintext()->kind)->toBe(TypeKind::Plaintext)
        ->and(SealType::tryFromTag('dec:30')?->scale)->toBe(30)
        ->and(SealType::tryFromTag('bool')?->equals(SealType::boolean()))->toBeTrue()
        ->and(SealType::string()->equals(SealType::integer()))->toBeFalse();

    foreach (['dec:31', 'dec:02', 'dec', 'flt:-1', 'null', 'nope', 'dec:2 '] as $invalid) {
        expect(SealType::tryFromTag($invalid))->toBeNull();
    }

    foreach (['str', 'int', 'bool', 'dt', 'date', 'json', 'bin', 'auto', 'plain'] as $tag) {
        expect(SealType::tryFromTag($tag)?->tag())->toBe($tag);
    }

    expect(fn () => SealType::decimal(31))->toThrow(InvalidSealDefinitionException::class, 'between 0 and 30')
        ->and(fn () => SealType::float(-1))->toThrow(InvalidSealDefinitionException::class);
});

it('lists every definition problem at once', function (): void {
    $exception = InvalidSealDefinitionException::forClass('App\\Models\\Invoice', ['no seals', 'bad ring']);

    expect($exception->problems())->toBe(['no seals', 'bad ring'])
        ->and($exception->getMessage())->toContain('App\\Models\\Invoice')->toContain('- bad ring')
        ->and(InvalidSealDefinitionException::invalidScale(40, 30)->problems())->toBe(['scale 40 is outside 0..30']);
});
