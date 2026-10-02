<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Nonces\Stores;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\LockableCache;

/**
 * Nonce digests in a cache store that supports atomic locks: consuming or remembering is one
 * atomic `add()` of a `…:used` marker; entries expire with the nonce.
 *
 * @internal
 */
final readonly class CacheNonceStore implements NonceStore
{
    public function __construct(private Repository $cache)
    {
        LockableCache::locks($cache, 'nonces.cache_store');
    }

    public function issue(string $purpose, string $digest, CarbonImmutable $expiresAt, ?Model $subject): void
    {
        $this->cache->put(self::key($purpose, $digest, 'issued'), [
            'subject' => self::subject($subject),
            'expires' => $expiresAt->getTimestamp(),
        ], max(1, $expiresAt->getTimestamp() - Clock::now()->getTimestamp()));
    }

    public function consume(string $purpose, string $digest, CarbonImmutable $now, ?Model $subject): bool
    {
        $issued = $this->cache->get(self::key($purpose, $digest, 'issued'));

        if (! is_array($issued) || ! is_int($issued['expires'] ?? null) || $issued['expires'] <= $now->getTimestamp() || ($issued['subject'] ?? null) !== self::subject($subject)) {
            return false;
        }

        return $this->cache->add(self::key($purpose, $digest, 'used'), 1, max(1, $issued['expires'] - $now->getTimestamp()));
    }

    public function remember(string $purpose, string $digest, CarbonImmutable $until, CarbonImmutable $now): bool
    {
        return $this->cache->add(self::key($purpose, $digest, 'used'), 1, max(1, $until->getTimestamp() - $now->getTimestamp()));
    }

    public function prune(CarbonImmutable $now): int
    {
        return 0;
    }

    private static function key(string $purpose, string $digest, string $suffix): string
    {
        return "sentinel:nonce:{$purpose}:{$digest}:{$suffix}";
    }

    private static function subject(?Model $subject): ?string
    {
        return $subject === null ? null : $subject->getMorphClass().':'.$subject->getKey();
    }
}
