<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use RoundlyConsulting\Sentinel\Keys\CryptoErrors;

/**
 * crypto-for-laravel failures become Sentinel's in one place. The "missing extension" path
 * cannot happen on a PHP build with ext-sodium and OpenSSL, so it is pinned here directly.
 */
it('passes results through untouched', function (): void {
    expect(CryptoErrors::translate(Algorithm::Ed25519, static fn (): string => 'signature'))->toBe('signature');
});

it('reports a missing capability as an unsupported algorithm', function (): void {
    try {
        CryptoErrors::translate(Algorithm::Ed25519, static fn (): never => throw UnsupportedAlgorithmException::sodiumMissing());
        $this->fail('expected an exception');
    } catch (InvalidKeyMaterialException $exception) {
        expect($exception->getMessage())->toContain('ed25519 algorithm is not available')
            ->and($exception->getPrevious())->toBeInstanceOf(UnsupportedAlgorithmException::class);
    }
});

it('names a crypto refusal when the caller says what was wrong', function (): void {
    try {
        CryptoErrors::translate(Algorithm::EcdsaP256Sha256, static fn (): never => throw WeakKeyException::emptySecret(), 'the signature could not be produced');
        $this->fail('expected an exception');
    } catch (InvalidKeyMaterialException $exception) {
        expect($exception->getMessage())->toBe('The key material is not a valid ecdsa-p256-sha256 key: the signature could not be produced.')
            ->and($exception->getPrevious())->toBeInstanceOf(WeakKeyException::class);
    }
});

it('lets any other crypto refusal through unchanged', function (): void {
    $refusal = WeakKeyException::emptySecret();

    expect(fn () => CryptoErrors::translate(Algorithm::HmacSha256, static fn (): never => throw $refusal))
        ->toThrow(fn (WeakKeyException $thrown) => expect($thrown)->toBe($refusal));
});
