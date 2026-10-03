<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency;

use Carbon\CarbonImmutable;

/**
 * The state of one key as every store holds it: the scope and fingerprint it was first seen
 * with, `processing` with an owner lease or `completed` with a stored response.
 *
 * @internal
 */
final readonly class IdempotencyRecord
{
    public function __construct(
        public string $scope,
        public string $fingerprint,
        public bool $completed,
        public string $ownerToken,
        public CarbonImmutable $lockedUntil,
        public ?string $response,
        public ?int $responseStatus,
        public bool $replayable,
        public ?CarbonImmutable $completedAt,
        public CarbonImmutable $expiresAt,
        public CarbonImmutable $createdAt,
    ) {}

    public static function owned(string $scope, string $fingerprint, string $token, CarbonImmutable $now, int $lockSeconds, int $ttl): self
    {
        return new self($scope, $fingerprint, false, $token, $now->addSeconds($lockSeconds), null, null, true, null, $now->addSeconds($ttl), $now);
    }

    /**
     * A key ends with its TTL — but never while a live lease still holds it: the request that
     * owns it is running, and a duplicate must not run beside it.
     */
    public function expired(CarbonImmutable $now): bool
    {
        return $this->expiresAt->lte($now) && ($this->completed || $this->lockedUntil->lte($now));
    }

    /**
     * Until when the record must be kept: its TTL, or the end of a live lease when later.
     */
    public function keepUntil(): CarbonImmutable
    {
        return ! $this->completed && $this->lockedUntil->gt($this->expiresAt) ? $this->lockedUntil : $this->expiresAt;
    }

    public function leasedTo(string $token, CarbonImmutable $now, int $lockSeconds): self
    {
        return new self(
            $this->scope, $this->fingerprint, false, $token, $now->addSeconds($lockSeconds), null, null, true, null, $this->expiresAt, $this->createdAt,
        );
    }

    public function completedWith(?string $response, int $status, bool $replayable, CarbonImmutable $now): self
    {
        return new self(
            $this->scope, $this->fingerprint, true, $this->ownerToken, $this->lockedUntil, $response, $status, $replayable, $now, $this->expiresAt, $this->createdAt,
        );
    }
}
