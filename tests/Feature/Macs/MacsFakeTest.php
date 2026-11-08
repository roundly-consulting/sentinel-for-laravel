<?php

declare(strict_types=1);

use PHPUnit\Framework\ExpectationFailedException;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Testing\RecordedCall;
use RoundlyConsulting\Sentinel\Testing\SentinelFake;

/**
 * `Sentinel::macs()` under `Sentinel::fake()`: stateless, so the fake returns the real MAC and
 * the real index — a host test gets byte-correct signatures — and records each call without
 * the secrets (only their count) or the MAC handed to `verify()`.
 */

/**
 * Whatever a call returns or throws, comparable across the real manager and the fake.
 */
function observeMacs(Closure $call): mixed
{
    try {
        return ['result' => $call()];
    } catch (Throwable $exception) {
        return ['exception' => $exception::class, 'message' => $exception->getMessage()];
    }
}

it('gives the real result or exception under the fake', function (Closure $call): void {
    $real = observeMacs($call);

    Sentinel::fake();

    expect(observeMacs($call))->toBe($real)
        ->and(app(SentinelManager::class))->toBeInstanceOf(SentinelFake::class);
})->with([
    'sign M-1' => [static fn (): string => bin2hex(Sentinel::macs()->sign(macsVector('M-1')['message'], macsVector('M-1')['secret']))],
    'sign M-3 sha512' => [static fn (): string => bin2hex(Sentinel::macs()->sign(macsVector('M-3')['message'], macsVector('M-3')['secret'], Algorithm::HmacSha512))],
    'sign M-4 long key' => [static fn (): string => bin2hex(Sentinel::macs()->sign(macsVector('M-4')['message'], macsVector('M-4')['secret']))],
    'verify M-6' => [static fn (): ?int => Sentinel::macs()->verify(macsVector('M-6')['message'], macsVector('M-6')['mac'], [macsVector('M-6')['secret']])],
    'verify rotation' => [static fn (): ?int => Sentinel::macs()->verify(macsVector('M-7')['message'], macsVector('M-7')['mac'], [macsVector('M-8')['secret'], macsVector('M-7')['secret']])],
    'verify the same secret twice' => [static fn (): ?int => Sentinel::macs()->verify(macsVector('M-7')['message'], macsVector('M-7')['mac'], [macsVector('M-7')['secret'], macsVector('M-7')['secret']])],
    'verify no match' => [static fn (): ?int => Sentinel::macs()->verify(macsVector('M-7')['message'], macsVector('M-7')['mac'], [macsVector('M-8')['secret']])],
    'verify wrong length' => [static fn (): ?int => Sentinel::macs()->verify('m', str_repeat("\0", 31), ['k'])],
    'verify sha512 as sha256' => [static fn (): ?int => Sentinel::macs()->verify(macsVector('M-3')['message'], macsVector('M-3')['mac'], [macsVector('M-3')['secret']])],
    'no secrets' => [static fn (): ?int => Sentinel::macs()->verify('m', 'mac', [])],
    'too many secrets' => [static fn (): ?int => Sentinel::macs()->verify('m', 'mac', array_fill(0, 9, 'k'))],
    'empty secret after a match' => [static fn (): ?int => Sentinel::macs()->verify(macsVector('M-5')['message'], macsVector('M-5')['mac'], ['k', ''])],
    'empty secret when signing' => [static fn (): string => Sentinel::macs()->sign('m', '')],
    'not a list' => [static fn (): ?int => Sentinel::verifyWithSecrets('m', 'mac', ['a' => 'k'])],
    'sign ed25519' => [static fn (): string => Sentinel::macs()->sign('m', 'k', Algorithm::Ed25519)],
    'verify ecdsa' => [static fn (): ?int => Sentinel::macs()->verify('m', 'mac', ['k'], Algorithm::EcdsaP256Sha256)],
]);

it('records sign and verify calls without any secret or the verified MAC', function (): void {
    $fake = Sentinel::fake();
    $vector = macsVector('M-7');
    $grace = macsVector('M-8')['secret'];

    $mac = Sentinel::macs()->sign($vector['message'], $vector['secret']);
    app(SentinelManager::class)->macs()->verify($vector['message'], $vector['mac'], [$grace, $vector['secret']]);
    Sentinel::verifyWithSecrets('other', $vector['mac'], [$grace], Algorithm::HmacSha256);

    $signed = $fake->recorded('signWithSecret');
    $verified = $fake->recorded('verifyWithSecrets');

    expect($signed)->toHaveCount(1)
        ->and($signed[0]->arguments)->toBe([$vector['message'], Algorithm::HmacSha256])
        ->and($signed[0]->result)->toBe($mac)
        ->and($verified)->toHaveCount(2)
        ->and($verified[0]->arguments)->toBe([$vector['message'], Algorithm::HmacSha256, 2])
        ->and($verified[0]->result)->toBe(1)
        ->and($verified[1]->arguments)->toBe(['other', Algorithm::HmacSha256, 1])
        ->and($verified[1]->result)->toBeNull();

    $calls = [...$signed, ...$verified];
    $dumps = serialize($calls).var_export($calls, true).json_encode($calls, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE).print_r($calls, true);

    foreach ([$vector['secret'], $grace, bin2hex($vector['secret']), bin2hex($grace), base64_encode($vector['secret']), base64_encode($grace), bin2hex($vector['mac'])] as $needle) {
        expect($dumps)->not->toContain($needle);
    }
});

it('records no call that a production rule refused', function (): void {
    $fake = Sentinel::fake();

    try {
        Sentinel::macs()->verify('m', 'mac', []);
    } catch (InvalidKeyMaterialException) {
    }

    try {
        Sentinel::macs()->sign('m', 'k', Algorithm::Ed25519);
    } catch (AlgorithmNotAllowedException) {
    }

    expect($fake->recorded('signWithSecret'))->toBe([])
        ->and($fake->recorded('verifyWithSecrets'))->toBe([]);

    $fake->assertNoMacsWithSecrets();
});

it('scripts a refusal with rejectMacsWithSecrets() while keeping the production rules', function (): void {
    $fake = Sentinel::fake()->rejectMacsWithSecrets();
    $vector = macsVector('M-7');

    expect(Sentinel::macs()->verify($vector['message'], $vector['mac'], [$vector['secret']]))->toBeNull()
        ->and(Sentinel::macs()->sign($vector['message'], $vector['secret']))->toBe($vector['mac'])
        ->and(fn () => Sentinel::macs()->verify('m', 'mac', ['']))->toThrow(InvalidKeyMaterialException::class)
        ->and(fn () => Sentinel::macs()->verify('m', 'mac', ['k'], Algorithm::Ed25519))->toThrow(AlgorithmNotAllowedException::class)
        ->and($fake->recorded('verifyWithSecrets')[0]->result)->toBeNull();

    $fake->assertMacsVerified($vector['message'], matched: false);
    expect(fn () => $fake->assertMacsVerified(matched: true))->toThrow(ExpectationFailedException::class);
});

it('passes and fails assertMacSigned', function (): void {
    $fake = Sentinel::fake();

    expect(fn () => $fake->assertMacSigned())->toThrow(ExpectationFailedException::class, 'Expected a MAC to be signed with a caller-held secret, but none was.');

    Sentinel::macs()->sign('payload', 'k', Algorithm::HmacSha512);

    $fake->assertMacSigned();
    $fake->assertMacSigned('payload');
    $fake->assertMacSigned('payload', Algorithm::HmacSha512);
    Sentinel::assertMacSigned(algorithm: Algorithm::HmacSha512);

    expect(fn () => $fake->assertMacSigned('other'))->toThrow(ExpectationFailedException::class, 'over [other]')
        ->and(fn () => $fake->assertMacSigned(algorithm: Algorithm::HmacSha256))->toThrow(ExpectationFailedException::class, 'with [hmac-sha256]')
        ->and(fn () => $fake->assertMacSigned('payload', Algorithm::HmacSha384))->toThrow(ExpectationFailedException::class, 'over [payload] with [hmac-sha384]');
});

it('passes and fails assertMacsVerified', function (): void {
    $fake = Sentinel::fake();
    $vector = macsVector('M-5');

    expect(fn () => $fake->assertMacsVerified())->toThrow(ExpectationFailedException::class, 'Expected a MAC to be verified against caller-held secrets, but none was.');

    Sentinel::macs()->verify($vector['message'], $vector['mac'], [$vector['secret']]);

    $fake->assertMacsVerified();
    $fake->assertMacsVerified($vector['message']);
    $fake->assertMacsVerified($vector['message'], matched: true);
    Sentinel::assertMacsVerified(matched: true);

    expect(fn () => $fake->assertMacsVerified(matched: false))->toThrow(ExpectationFailedException::class, 'that matched no secret')
        ->and(fn () => $fake->assertMacsVerified('other'))->toThrow(ExpectationFailedException::class, 'over [other]')
        ->and(fn () => $fake->assertMacsVerified('other', true))->toThrow(ExpectationFailedException::class, 'over [other] that matched a secret');
});

it('passes and fails assertNoMacsWithSecrets', function (string $method): void {
    $fake = Sentinel::fake();

    $fake->assertNoMacsWithSecrets();
    Sentinel::assertNoMacsWithSecrets();

    $method === 'sign' ? Sentinel::macs()->sign('m', 'k') : Sentinel::macs()->verify('m', 'mac', ['k']);

    expect(fn () => $fake->assertNoMacsWithSecrets())->toThrow(ExpectationFailedException::class, 'Expected no MAC with caller-held secrets, but 1 was.');

    Sentinel::macs()->sign('m', 'k');

    expect(fn () => $fake->assertNoMacsWithSecrets())->toThrow(ExpectationFailedException::class, 'but 2 were.');
})->with(['sign', 'verify']);

it('keeps the ring MAC assertions apart from the caller-held-secret ones', function (): void {
    $fake = Sentinel::fake();

    Sentinel::macs()->sign('m', 'k');
    Sentinel::macs()->verify('m', 'mac', ['k']);

    $fake->assertNoMacsComputed();
    $fake->assertMacNotVerified();

    expect(array_map(static fn (RecordedCall $call): string => $call->method, $fake->recorded()))->toBe(['signWithSecret', 'verifyWithSecrets']);
});
