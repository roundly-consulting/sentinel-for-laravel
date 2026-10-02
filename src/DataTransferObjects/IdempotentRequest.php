<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

/**
 * One idempotent request as a store sees it: the key's digest (never the key), its scope,
 * the payload fingerprint, the TTL and — once owned — the owner token.
 *
 * @internal
 */
final readonly class IdempotentRequest
{
    public function __construct(
        public string $keyDigest,
        public string $scope,
        public string $fingerprint,
        public int $ttl,
        public ?string $ownerToken = null,
    ) {}

    public function ownedBy(string $token): self
    {
        return new self($this->keyDigest, $this->scope, $this->fingerprint, $this->ttl, $token);
    }
}
