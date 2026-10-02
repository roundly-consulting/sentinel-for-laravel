<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Keys\KeyCache;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * §10 item 35 (keys part): decrypted keys live in a scoped cache that Laravel resets between
 * Octane requests and queued jobs; the singletons hold no request state.
 */
it('gives every request (or job) a fresh key cache', function (): void {
    $first = app(KeyCache::class);
    $store = app(KeyStoreManager::class)->ring('default');

    expect(app(KeyCache::class))->toBe($first)
        ->and(app(KeyStoreManager::class)->ring('default'))->toBe($store);

    // What Octane and the queue worker do between units of work.
    app()->forgetScopedInstances();

    expect(app(KeyCache::class))->not->toBe($first)
        ->and(app(KeyStoreManager::class)->ring('default'))->not->toBe($store)
        ->and(app(KeyStoreManager::class))->toBe(app(KeyStoreManager::class))
        ->and(app(SentinelManager::class))->toBe(app(SentinelManager::class));
});

it('sees a config change after the request boundary, never a stale key', function (): void {
    expect(app(KeyStoreManager::class)->signingKey('default')->keyId)->toBe('test-default');

    config()->set('sentinel.keys.rings.default.key_id', 'rotated');
    app()->forgetScopedInstances();

    expect(app(KeyStoreManager::class)->signingKey('default')->keyId)->toBe('rotated');
});

it('holds no key cache inside the singleton manager', function (): void {
    $properties = array_map(
        static fn (ReflectionProperty $property): string => (string) $property->getType(),
        (new ReflectionClass(KeyStoreManager::class))->getProperties(),
    );

    expect($properties)->not->toContain(KeyCache::class);
});
