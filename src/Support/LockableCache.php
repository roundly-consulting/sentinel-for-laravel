<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Illuminate\Cache\NullStore;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;

/**
 * Cache-backed idempotency and nonce stores rely on atomic locks and `add()`: a store
 * without locks (APC), or one that stores nothing (`null`, whose locks always succeed), would
 * silently drop every guarantee — refuse it instead.
 *
 * @internal
 */
final class LockableCache
{
    public static function locks(Repository $cache, string $key): LockProvider
    {
        $store = $cache->getStore();

        if (! $store instanceof LockProvider || $store instanceof NullStore) {
            throw InvalidSentinelConfigurationException::lockStoreRequired($key);
        }

        return $store;
    }
}
