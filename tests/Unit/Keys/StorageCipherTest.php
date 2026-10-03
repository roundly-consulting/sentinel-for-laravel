<?php

declare(strict_types=1);

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Encryption\MissingAppKeyException;
use RoundlyConsulting\Sentinel\Keys\StorageCipher;

it('opens with a previous APP_KEY and always encrypts with the current one (dual-review O-3)', function (): void {
    $cipher = app(StorageCipher::class);
    $old = $cipher->encrypt(StorageCipher::IDEMPOTENT_RESPONSE, 'payload', 'id');

    config()->set('app.previous_keys', ['', 42, config('app.key')]);
    config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    $new = $cipher->encrypt(StorageCipher::IDEMPOTENT_RESPONSE, 'payload', 'id');

    expect($cipher->decrypt(StorageCipher::IDEMPOTENT_RESPONSE, $old, 'id'))->toBe('payload')
        ->and($cipher->decrypt(StorageCipher::IDEMPOTENT_RESPONSE, $new, 'id'))->toBe('payload');

    config()->set('app.previous_keys', []);

    expect(fn () => $cipher->decrypt(StorageCipher::IDEMPOTENT_RESPONSE, $old, 'id'))->toThrow(DecryptException::class, 'authenticated')
        ->and($cipher->decrypt(StorageCipher::IDEMPOTENT_RESPONSE, $new, 'id'))->toBe('payload');
});

it('takes a raw or malformed APP_KEY as key material, and refuses none (dual-review O-3)', function (string $appKey): void {
    config()->set('app.key', $appKey);
    $cipher = app(StorageCipher::class);

    expect($cipher->decrypt(StorageCipher::KEY_ENVELOPE, $cipher->encrypt(StorageCipher::KEY_ENVELOPE, 'x', 'id'), 'id'))->toBe('x');
})->with([
    'raw 32 characters' => ['abcdefghijklmnopqrstuvwxyz012345'],
    'malformed base64' => ['base64:!!not base64!!'],
]);

it('refuses to encrypt without an APP_KEY', function (mixed $appKey): void {
    config()->set('app.key', $appKey);

    expect(fn () => app(StorageCipher::class)->encrypt(StorageCipher::KEY_ENVELOPE, 'x', 'id'))->toThrow(MissingAppKeyException::class);
})->with([null, '']);
