<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Ledger\Anchors;

use Illuminate\Contracts\Cache\Repository;
use RoundlyConsulting\Sentinel\Contracts\Anchor;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;
use RoundlyConsulting\Sentinel\Ledger\AnchorCodec;

/**
 * The newest checkpoint per connection in a cache store (`{key}:{connection}`, forever).
 * Use a store the database writer cannot reach (a separate Redis).
 *
 * @internal
 */
final readonly class CacheAnchor implements Anchor
{
    public function __construct(
        private Repository $cache,
        private string $key,
    ) {}

    public function name(): string
    {
        return 'cache';
    }

    public function publish(AnchorPayload $payload): void
    {
        $this->cache->forever($this->key.':'.$payload->connection, AnchorCodec::encode($payload));
    }

    public function latest(string $connection): ?AnchorPayload
    {
        $stored = $this->cache->get($this->key.':'.$connection);

        return $stored === null ? null : AnchorCodec::decode(is_string($stored) ? $stored : '');
    }
}
