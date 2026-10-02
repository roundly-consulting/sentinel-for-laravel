<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\CanonicalizationException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;

it('roots every exception in SentinelException', function (SentinelException $exception): void {
    expect($exception)->toBeInstanceOf(RuntimeException::class);
})->with([
    fn () => AlgorithmNotAllowedException::forRing('default', Algorithm::Ed25519),
    fn () => CanonicalizationException::invalidJson(),
    fn () => InvalidKeyMaterialException::encodingRequired(),
    fn () => InvalidSentinelConfigurationException::invalidValue('context', 'is wrong'),
]);

it('names the refused algorithm, seal and ring', function (): void {
    expect(AlgorithmNotAllowedException::forSeal('App\\Models\\Invoice', 'financial', Algorithm::HmacSha512)->getMessage())
        ->toContain('hmac-sha512')->toContain('financial')->toContain('App\\Models\\Invoice')
        ->and(AlgorithmNotAllowedException::forRing('http', Algorithm::HmacSha384)->getMessage())->toContain('[http]');
});

it('never echoes an attacker-shaped algorithm name', function (): void {
    expect(AlgorithmNotAllowedException::unknownName('none', 'keys.rings.default.algorithms')->getMessage())->toContain('[none]')
        ->and(AlgorithmNotAllowedException::unknownName("<script>\n", 'x')->getMessage())->toContain('(invalid)')->not->toContain('<script>');
});

it('keeps canonicalization reasons machine-readable', function (Closure $make, string $reason): void {
    /** @var CanonicalizationException $exception */
    $exception = $make();

    expect($exception->reason())->toBe($reason)
        ->and($exception->field())->toBeNull()
        ->and($exception->forField('a:x')->field())->toBe('a:x')
        ->and($exception->forField('a:x')->reason())->toBe($reason);
})->with([
    [fn () => CanonicalizationException::invalidUtf8(), 'invalid_utf8'],
    [fn () => CanonicalizationException::notInteger(), 'not_integer'],
    [fn () => CanonicalizationException::notRepresentable(), 'not_representable'],
    [fn () => CanonicalizationException::notBoolean(), 'not_boolean'],
    [fn () => CanonicalizationException::invalidDatetime(), 'invalid_datetime'],
    [fn () => CanonicalizationException::invalidDate(), 'invalid_date'],
    [fn () => CanonicalizationException::invalidJson(), 'invalid_json'],
    [fn () => CanonicalizationException::floatRequiresDeclaration(), 'float_requires_declaration'],
    [fn () => CanonicalizationException::computedModel(), 'computed_model'],
    [fn () => CanonicalizationException::unsupportedType('resource'), 'unsupported_type'],
]);

it('returns the same exception when it already names the field', function (): void {
    $exception = CanonicalizationException::notBoolean('a:paid');

    expect($exception->forField('a:paid'))->toBe($exception);
});
