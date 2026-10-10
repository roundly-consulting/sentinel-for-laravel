<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys\Stores;

use RoundlyConsulting\Sentinel\Contracts\KeyStore;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Keys\SealingKey;

/**
 * Several drivers as one ring (`drivers` order): the first that has a signing key signs; a
 * `kid` resolves in the first driver that knows it.
 *
 * @internal
 */
final readonly class ChainKeyStore implements KeyStore
{
    /**
     * @param  list<KeyStore>  $stores
     * @param  list<string>  $revoked  `ring:kid` entries of `sentinel.keys.revoked`
     */
    public function __construct(
        private string $ring,
        private array $stores,
        private array $revoked = [],
    ) {}

    public function signingKey(): SealingKey
    {
        foreach ($this->stores as $store) {
            try {
                $key = $store->signingKey();
            } catch (NoSigningKeyException) {
                continue;
            }

            // The built-in stores skip a revoked key themselves; a custom one never sees the list,
            // so its revoked key must not end the search either.
            if (! in_array("{$key->ring}:{$key->keyId}", $this->revoked, true)) {
                return $key;
            }
        }

        throw NoSigningKeyException::forRing($this->ring);
    }

    public function find(string $keyId): ?SealingKey
    {
        foreach ($this->stores as $store) {
            $key = $store->find($keyId);

            if ($key !== null) {
                return $key;
            }
        }

        return null;
    }

    public function all(): array
    {
        return array_merge(...array_map(static fn (KeyStore $store): array => $store->all(), $this->stores));
    }

    public function supportsWrites(): bool
    {
        foreach ($this->stores as $store) {
            if ($store->supportsWrites()) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<KeyStore>
     */
    public function stores(): array
    {
        return $this->stores;
    }
}
