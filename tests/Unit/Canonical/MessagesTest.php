<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Canonical\FieldTagger;
use RoundlyConsulting\Sentinel\Canonical\FieldValue;
use RoundlyConsulting\Sentinel\Canonical\LedgerMessage;
use RoundlyConsulting\Sentinel\Canonical\SealMessage;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\SealingKey;

function sealMessage(array $overrides = []): SealMessage
{
    $values = [
        'context' => '', 'type' => 'invoice', 'table' => 'invoices', 'id' => '1', 'scope' => '', 'seal' => 'financial',
        'version' => 1, 'previous' => null, 'ring' => 'default', 'keyId' => 'k1', 'algorithm' => Algorithm::HmacSha256,
        'at' => CarbonImmutable::parse('2026-10-02 20:30:00.5', 'Europe/Bratislava'),
        'fields' => [new FieldValue('a:b', 'str', 'x'), new FieldValue('a:a', 'int', '1')],
        ...$overrides,
    ];

    return new SealMessage(...$values);
}

it('binds every identity member, so changing any one changes the bytes', function (string $member, mixed $value): void {
    expect(sealMessage([$member => $value])->bytes())->not->toBe(sealMessage()->bytes());
})->with([
    ['context', 'other-app'], ['type', 'App\\Models\\Invoice'], ['table', 'archived_invoices'], ['id', '2'],
    ['scope', 'tenant-2'], ['seal', 'identity'], ['version', 2], ['previous', 'abc'], ['ring', 'financial'],
    ['keyId', 'k2'], ['algorithm', Algorithm::HmacSha512],
]);

it('writes UTC microsecond timestamps and sorts fields by name', function (): void {
    $bytes = sealMessage()->bytes();

    expect($bytes)->toContain('"at":"2026-10-02T18:30:00.500000Z"')
        ->toContain('"f":[["a:a","int","1"],["a:b","str","x"]]')
        ->toStartWith('{"alg":"hmac-sha256",')
        ->toEndWith('"v":"sentinel.seal/1","ver":"1"}');
});

it('sorts the changed attribute names of a ledger entry', function (): void {
    $message = new LedgerMessage('', 'invoice', '1', 'financial', 3, SealEvent::Acknowledged, 'default', 'k1', Algorithm::HmacSha256,
        null, null, ['a:z', 'a:a', 'c:m'], null, null, 'reason', CarbonImmutable::parse('2026-10-02 18:30:00', 'UTC'));

    expect($message->bytes())->toContain('"changed":["a:a","a:z","c:m"]')->toContain('"mac":null');
});

it('tags fields for HMAC keys only and diffs tags in constant time', function (): void {
    $tagger = new FieldTagger;
    $hmac = new SealingKey('default', 'k1', KeyMaterial::generate(Algorithm::HmacSha256));
    $ed = new SealingKey('default', 'k1', KeyMaterial::generate(Algorithm::Ed25519));

    $original = $tagger->tags($hmac, sealMessage());
    $tampered = $tagger->tags($hmac, sealMessage(['fields' => [new FieldValue('a:b', 'str', 'y'), new FieldValue('a:a', 'int', '1')]]));

    expect($original)->toHaveKeys(['a:a', 'a:b'])
        ->and(strlen((string) $original['a:a']))->toBe(22)
        ->and($tagger->tags($ed, sealMessage()))->toBeNull()
        ->and($tagger->changed((array) $original, (array) $original))->toBe([])
        ->and($tagger->changed((array) $original, (array) $tampered))->toBe(['a:b'])
        ->and($tagger->changed(['a:a' => $original['a:a'], 'a:old' => 'x'], (array) $original))->toBe(['a:b', 'a:old'])
        ->and($tagger->changed(['a:a' => 5, 'a:b' => $original['a:b']], (array) $original))->toBe(['a:a']);
});
