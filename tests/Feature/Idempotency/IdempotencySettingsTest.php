<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * §10 item 57 (idempotency, nonces, problems): invalid values fail loudly with the key name.
 */
it('reads the idempotency, nonce and problem settings', function (): void {
    config()->set('sentinel.idempotency.methods', ['post', 'Delete']);
    config()->set('sentinel.idempotency.replayed_headers', ['Content-Type', 'Set-Cookie', 'etag']);
    config()->set('sentinel.idempotency.cache_store', '');
    config()->set('sentinel.problems.type_base', 'https://errors.example.com/sentinel');

    expect(Settings::idempotencyMethods())->toBe(['POST', 'DELETE'])
        ->and(Settings::replayedHeaders())->toBe(['content-type', 'etag'])
        ->and(Settings::idempotencyCacheStore())->toBeNull()
        ->and(Settings::nonceCacheStore())->toBeNull()
        ->and(Settings::problemTypeBase())->toBe('https://errors.example.com/sentinel')
        ->and(Settings::idempotencyHeader())->toBe('Idempotency-Key')
        ->and(Settings::replayHeader())->toBe('Idempotent-Replayed');
});

it('refuses invalid idempotency, nonce and problem settings', function (string $key, mixed $value, Closure $read): void {
    config()->set($key, $value);

    expect($read)->toThrow(InvalidSentinelConfigurationException::class, substr($key, 9));
})->with([
    ['sentinel.idempotency.methods', [], fn () => Settings::idempotencyMethods()],
    ['sentinel.idempotency.methods', ['PO ST'], fn () => Settings::idempotencyMethods()],
    ['sentinel.idempotency.replayed_headers', 'etag', fn () => Settings::replayedHeaders()],
    ['sentinel.idempotency.replayed_headers', ['bad header'], fn () => Settings::replayedHeaders()],
    ['sentinel.idempotency.header', 'Bad Header', fn () => Settings::idempotencyHeader()],
    ['sentinel.idempotency.replay_header', 7, fn () => Settings::replayHeader()],
    ['sentinel.idempotency.store', 'Redis Cluster', fn () => Settings::idempotencyStore()],
    ['sentinel.idempotency.cache_store', 7, fn () => Settings::idempotencyCacheStore()],
    ['sentinel.idempotency.ttl', 10, fn () => Settings::idempotencyTtl()],
    ['sentinel.idempotency.lock_seconds', 0, fn () => Settings::idempotencyLockSeconds()],
    ['sentinel.idempotency.min_length', 0, fn () => Settings::idempotencyMinLength()],
    ['sentinel.idempotency.max_length', 300, fn () => Settings::idempotencyMaxLength()],
    ['sentinel.idempotency.max_response_bytes', 10, fn () => Settings::maxResponseBytes()],
    ['sentinel.nonces.ttl', 0, fn () => Settings::nonceTtl()],
    ['sentinel.nonces.length', 16, fn () => Settings::nonceLength()],
    ['sentinel.problems.type_base', 'not a url', fn () => Settings::problemTypeBase()],
]);
