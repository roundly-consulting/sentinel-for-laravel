<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use Closure;
use RoundlyConsulting\Sentinel\Contracts\KeyStore;

/**
 * The per-request memo of key stores (and so of decrypted key material). Bound **scoped**:
 * Laravel drops it between Octane requests and queued jobs, so material never outlives the
 * unit of work that loaded it.
 *
 * @internal
 */
final class KeyCache
{
    /** @var array<string, KeyStore> */
    private array $stores = [];

    /** @var array<string, true> */
    private array $integrityFailures = [];

    /**
     * @param  Closure(): KeyStore  $make
     */
    public function store(string $ring, Closure $make): KeyStore
    {
        return $this->stores[$ring] ??= $make();
    }

    public function markIntegrityFailure(string $ring, string $keyId): void
    {
        $this->integrityFailures["{$ring}:{$keyId}"] = true;
    }

    public function integrityFailed(string $ring, string $keyId): bool
    {
        return isset($this->integrityFailures["{$ring}:{$keyId}"]);
    }

    /**
     * Forget loaded stores (after a key write, or a config change in tests).
     */
    public function forget(): void
    {
        $this->stores = [];
        $this->integrityFailures = [];
    }
}
