<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;
use RoundlyConsulting\Sentinel\Idempotency\KeyParser;

/**
 * §10 item 40: the Idempotency-Key header (an RFC 9651 sf-string).
 */
it('reads an sf-string key and, by default, a bare one', function (string $header, string $key): void {
    expect(KeyParser::parse($header))->toBe($key);
})->with([
    'quoted' => ['"8e03978e-40d5-43e8-bc93-6894a57f9324"', '8e03978e-40d5-43e8-bc93-6894a57f9324'],
    'quoted with parameters' => ['"8e03978e-40d5-43e8-bc93-6894a57f9324";v=1', '8e03978e-40d5-43e8-bc93-6894a57f9324'],
    'escaped quote' => ['"key-with-\"quote\"-inside"', 'key-with-"quote"-inside'],
    'bare uuid' => ['8e03978e-40d5-43e8-bc93-6894a57f9324', '8e03978e-40d5-43e8-bc93-6894a57f9324'],
    'bare with symbols' => ['order_1234567890:retry#1', 'order_1234567890:retry#1'],
    'bare digits' => ['12345678901234567890', '12345678901234567890'],
]);

it('refuses keys that are not valid', function (string $header): void {
    expect(fn () => KeyParser::parse($header))->toThrow(InvalidIdempotencyKeyException::class);
})->with([
    'too short' => ['"short"'],
    'too long' => ['"'.str_repeat('k', 256).'"'],
    'empty' => ['""'],
    'unterminated' => ['"8e03978e-40d5-43e8-bc93'],
    'a control character' => ["\"8e03978e-40d5-43e8\x01bc93-6894a57f9324\""],
    'a space inside a bare key' => ['8e03978e 40d5 43e8 bc93 6894a57f9324'],
    'a list' => ['"8e03978e-40d5-43e8-aaaa", "8e03978e-40d5-43e8-bbbb"'],
    'a non-ASCII key' => ['"8e03978e-40d5-43e8-bc93-6894a57fé"'],
]);

it('accepts only sf-strings when unquoted keys are off', function (): void {
    config()->set('sentinel.idempotency.accept_unquoted', 'off');

    expect(KeyParser::parse('"8e03978e-40d5-43e8-bc93-6894a57f9324"'))->toBe('8e03978e-40d5-43e8-bc93-6894a57f9324')
        ->and(fn () => KeyParser::parse('8e03978e-40d5-43e8-bc93-6894a57f9324'))->toThrow(InvalidIdempotencyKeyException::class);
});

it('treats a missing header as no key and several header lines as invalid', function (): void {
    $none = Request::create('/orders', 'POST');
    $many = Request::create('/orders', 'POST');
    $many->headers->set('Idempotency-Key', ['"8e03978e-40d5-43e8-bc93-aaaaaaaaaaaa"', '"8e03978e-40d5-43e8-bc93-bbbbbbbbbbbb"']);

    expect(KeyParser::fromRequest($none))->toBeNull()
        ->and(fn () => KeyParser::fromRequest($many))->toThrow(InvalidIdempotencyKeyException::class);
});

it('honours the configured length bounds and header name', function (): void {
    config()->set('sentinel.idempotency.min_length', 4);
    config()->set('sentinel.idempotency.max_length', 8);
    config()->set('sentinel.idempotency.header', 'X-Request-Key');
    $request = Request::create('/orders', 'POST', server: ['HTTP_X_REQUEST_KEY' => '"abcd"']);

    expect(KeyParser::fromRequest($request))->toBe('abcd')
        ->and(fn () => KeyParser::parse('"abcdefghi"'))->toThrow(InvalidIdempotencyKeyException::class);
});
