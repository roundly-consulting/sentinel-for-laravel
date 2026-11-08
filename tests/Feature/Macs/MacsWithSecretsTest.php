<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Accessors\MacsAccessor;
use RoundlyConsulting\Sentinel\Actions\Macs\SignWithSecretAction;
use RoundlyConsulting\Sentinel\Actions\Macs\VerifyWithSecretsAction;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * `Sentinel::macs()` — HMAC with secrets the caller holds (webhooks, partner secrets): raw
 * bytes in and out, any non-empty secret length, verify against up to 8 secrets in constant
 * time with no early exit.
 */

/**
 * Count every MAC the actions compute, through the Signers seam.
 */
function countSecretMacs(): ArrayObject
{
    $count = new ArrayObject(['macs' => 0]);
    app()->instance(Signers::class, new Signers(onSecretMac: static function () use ($count): void {
        $count['macs']++;
    }));

    return $count;
}

it('signs every vector byte for byte and verifies it at index 0', function (string $id): void {
    $vector = macsVector($id);

    expect(Sentinel::macs()->sign($vector['message'], $vector['secret'], $vector['algorithm']))->toBe($vector['mac'])
        ->and(Sentinel::macs()->verify($vector['message'], $vector['mac'], [$vector['secret']], $vector['algorithm']))->toBe(0);
})->with(['M-1', 'M-2', 'M-3', 'M-4', 'M-5', 'M-6', 'M-7', 'M-8']);

it('defaults to hmac-sha256 and returns raw MACs of the hash length', function (): void {
    $vector = macsVector('M-1');

    expect(Sentinel::macs()->sign($vector['message'], $vector['secret']))->toBe($vector['mac'])
        ->and(Sentinel::macs()->verify($vector['message'], $vector['mac'], [$vector['secret']]))->toBe(0)
        ->and(strlen(Sentinel::macs()->sign('m', 'k', Algorithm::HmacSha384)))->toBe(48)
        ->and(strlen(Sentinel::macs()->sign('m', 'k', Algorithm::HmacSha512)))->toBe(64);
});

it('returns the index of the secret that matched — rotation with a grace secret', function (): void {
    $previous = macsVector('M-7');
    $current = macsVector('M-8');
    $message = $previous['message'];

    expect(Sentinel::macs()->verify($message, $previous['mac'], [$current['secret'], $previous['secret']]))->toBe(1)
        ->and(Sentinel::macs()->verify($message, $previous['mac'], [$previous['secret'], $current['secret']]))->toBe(0)
        ->and(Sentinel::macs()->verify($message, $current['mac'], [$previous['secret'], $current['secret']]))->toBe(1)
        ->and(Sentinel::macs()->verify($message, $previous['mac'], [$previous['secret'], $previous['secret']]))->toBe(0)
        ->and(Sentinel::macs()->verify($message, $previous['mac'], [$current['secret'], $current['secret'], $previous['secret'], $previous['secret']]))->toBe(2)
        ->and(Sentinel::macs()->verify($message, $previous['mac'], [$current['secret']]))->toBeNull()
        ->and(Sentinel::macs()->verify($message.' ', $previous['mac'], [$previous['secret']]))->toBeNull();
});

it('finds a match at the last of 8 secrets', function (): void {
    $vector = macsVector('M-5');
    $secrets = [...array_map(static fn (int $i): string => "other-{$i}", range(0, 6)), $vector['secret']];

    expect(Sentinel::macs()->verify($vector['message'], $vector['mac'], $secrets))->toBe(7);
});

it('returns null for a wrong-length MAC without throwing', function (string $mac): void {
    $vector = macsVector('M-7');

    expect(Sentinel::macs()->verify($vector['message'], $mac, [$vector['secret']]))->toBeNull();
})->with([
    '31 bytes' => [substr((string) base64_decode('dBcYxACDimm+8xx9Ykx71LVUgk5H4STQXxAUHZ5xcNk='), 0, 31)],
    '33 bytes' => [base64_decode('dBcYxACDimm+8xx9Ykx71LVUgk5H4STQXxAUHZ5xcNk=')."\0"],
    'empty' => [''],
    'base64 text instead of raw bytes' => ['dBcYxACDimm+8xx9Ykx71LVUgk5H4STQXxAUHZ5xcNk='],
    'all zeros' => [str_repeat("\0", 32)],
]);

it('refuses a sha512 MAC checked as sha256, and the reverse', function (): void {
    $sha512 = macsVector('M-3');
    $sha256 = macsVector('M-1');

    expect(Sentinel::macs()->verify($sha512['message'], $sha512['mac'], [$sha512['secret']], Algorithm::HmacSha256))->toBeNull()
        ->and(Sentinel::macs()->verify($sha256['message'], $sha256['mac'], [$sha256['secret']], Algorithm::HmacSha512))->toBeNull();
});

it('refuses an empty list of secrets', function (): void {
    Sentinel::macs()->verify('m', str_repeat("\0", 32), []);
})->throws(InvalidKeyMaterialException::class, 'at least one secret');

it('refuses more than 8 secrets', function (): void {
    Sentinel::macs()->verify('m', str_repeat("\0", 32), array_fill(0, MacsAccessor::MAX_SECRETS + 1, 'secret'));
})->throws(InvalidKeyMaterialException::class, 'at most 8 secrets');

it('accepts exactly 8 secrets', function (): void {
    expect(MacsAccessor::MAX_SECRETS)->toBe(8)
        ->and(Sentinel::macs()->verify('m', str_repeat("\0", 32), array_fill(0, 8, 'secret')))->toBeNull();
});

it('refuses an empty secret anywhere in the list before computing any MAC', function (array $secrets): void {
    $vector = macsVector('M-5');
    $count = countSecretMacs();

    expect(fn () => Sentinel::macs()->verify($vector['message'], $vector['mac'], $secrets))
        ->toThrow(InvalidKeyMaterialException::class, 'must not be empty')
        ->and($count['macs'])->toBe(0);
})->with([
    'alone' => [['']],
    'first' => [['', 'k']],
    'after a match' => [['k', '']],
    'last of 8' => [['a', 'b', 'c', 'd', 'e', 'f', 'k', '']],
]);

it('refuses an empty secret when signing before computing any MAC', function (): void {
    $count = countSecretMacs();

    expect(fn () => Sentinel::macs()->sign('m', ''))->toThrow(InvalidKeyMaterialException::class, 'must not be empty')
        ->and($count['macs'])->toBe(0);
});

it('refuses a non-list or a non-string secret', function (array $secrets): void {
    $count = countSecretMacs();

    expect(fn () => app(VerifyWithSecretsAction::class)->execute('m', str_repeat("\0", 32), $secrets))
        ->toThrow(InvalidArgumentException::class, 'list of strings')
        ->and($count['macs'])->toBe(0);
})->with([
    'string keys' => [['current' => 'k']],
    'gaps' => [[1 => 'k']],
    'an int' => [['k', 42]],
    'null' => [[null]],
    'an array' => [[['k']]],
]);

it('refuses an algorithm that computes no MAC, for sign and verify', function (Algorithm $algorithm): void {
    $count = countSecretMacs();

    expect(fn () => Sentinel::macs()->sign('m', 'k', $algorithm))
        ->toThrow(AlgorithmNotAllowedException::class, "[{$algorithm->value}]")
        ->and(fn () => Sentinel::macs()->verify('m', str_repeat("\0", 32), ['k'], $algorithm))
        ->toThrow(AlgorithmNotAllowedException::class, "[{$algorithm->value}]")
        ->and($count['macs'])->toBe(0);
})->with([Algorithm::Ed25519, Algorithm::EcdsaP256Sha256, Algorithm::EcdsaP384Sha384]);

it('computes the MAC of every secret — no early exit on a match or a miss', function (string $mac, ?int $expected): void {
    $vector = macsVector('M-5');
    $count = countSecretMacs();
    $secrets = [$vector['secret'], ...array_map(static fn (int $i): string => "other-{$i}", range(1, 7))];

    $mac = $mac === 'the vector' ? $vector['mac'] : $mac;

    expect(app(VerifyWithSecretsAction::class)->execute($vector['message'], $mac, $secrets))->toBe($expected)
        ->and($count['macs'])->toBe(8);
})->with([
    'match at index 0' => ['the vector', 0],
    'no match' => [str_repeat("\1", 32), null],
    'wrong length' => ['short', null],
]);

it('computes exactly one MAC when signing', function (): void {
    $count = countSecretMacs();

    app(SignWithSecretAction::class)->execute('m', 'k');

    expect($count['macs'])->toBe(1);
});

it('runs the same code through the facade, an injected manager and the raw actions (M-7)', function (): void {
    $vector = macsVector('M-7');
    $grace = macsVector('M-8')['secret'];

    $signed = [
        Sentinel::macs()->sign($vector['message'], $vector['secret']),
        Sentinel::signWithSecret($vector['message'], $vector['secret']),
        app(SentinelManager::class)->macs()->sign($vector['message'], $vector['secret']),
        app(SignWithSecretAction::class)->execute($vector['message'], $vector['secret']),
    ];
    $verified = [
        Sentinel::macs()->verify($vector['message'], $vector['mac'], [$grace, $vector['secret']]),
        Sentinel::verifyWithSecrets($vector['message'], $vector['mac'], [$grace, $vector['secret']]),
        app(SentinelManager::class)->macs()->verify($vector['message'], $vector['mac'], [$grace, $vector['secret']]),
        app(VerifyWithSecretsAction::class)->execute($vector['message'], $vector['mac'], [$grace, $vector['secret']]),
    ];

    expect($signed)->toBe(array_fill(0, 4, $vector['mac']))
        ->and($verified)->toBe(array_fill(0, 4, 1))
        ->and(Sentinel::macs())->toBeInstanceOf(MacsAccessor::class);
});

it('resolves the actions through the container so a host override applies', function (): void {
    app()->bind(VerifyWithSecretsAction::class, static fn (): never => throw new RuntimeException('overridden'));

    Sentinel::macs()->verify('m', 'mac', ['k']);
})->throws(RuntimeException::class, 'overridden');

it('needs no key ring, no database and no configured key', function (): void {
    config()->set('sentinel.keys.rings', []);
    $vector = macsVector('M-6');

    expect(Sentinel::macs()->verify($vector['message'], $vector['mac'], [$vector['secret']]))->toBe(0);
});

it('keeps the secret, the MAC and the message out of every refusal', function (Closure $call): void {
    try {
        $call();
        $this->fail('nothing thrown');
    } catch (Throwable $exception) {
        expect($exception->getMessage())->not->toContain('s3cr3t-value')->not->toContain('the-message')->not->toContain('mac-bytes');
    }
})->with([
    'not hmac' => [fn () => Sentinel::macs()->sign('the-message', 's3cr3t-value', Algorithm::Ed25519)],
    'empty secret' => [fn () => Sentinel::macs()->verify('the-message', 'mac-bytes', ['s3cr3t-value', ''])],
    'too many' => [fn () => Sentinel::macs()->verify('the-message', 'mac-bytes', array_fill(0, 9, 's3cr3t-value'))],
    'not a list' => [fn () => app(VerifyWithSecretsAction::class)->execute('the-message', 'mac-bytes', ['s3cr3t-value' => 's3cr3t-value'])],
]);
