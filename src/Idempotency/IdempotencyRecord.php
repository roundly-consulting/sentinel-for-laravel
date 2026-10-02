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
