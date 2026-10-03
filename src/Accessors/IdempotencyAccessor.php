<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Accessors;

use Closure;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentCall;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentResult;
use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;
use RoundlyConsulting\Sentinel\SentinelManager;
use SensitiveParameter;

/**
 * `Sentinel::idempotency()` — run work at most once per key outside HTTP (jobs, commands,
 * webhook handlers). Every call goes through the manager, so `Sentinel::fake()` sees it.
 */
final readonly class IdempotencyAccessor
{
    public function __construct(private SentinelManager $manager) {}

    /**
     * Run the callback once per (key, scope); a repeat returns the stored result. The key and
     * the scope are 1–255 bytes, a TTL 60–2 592 000 seconds, a lease (how long a running call
     * holds the key; null = `idempotency.lock_seconds`) 1–86 400 seconds.
     *
     * @throws InvalidIdempotencyKeyException
     */
    public function run(#[SensitiveParameter] string $key, string $scope, Closure $callback, ?string $fingerprint = null, ?int $ttl = null, ?int $lease = null): IdempotentResult
    {
        return $this->manager->runIdempotent(new IdempotentCall($key, $scope, $callback, $fingerprint, $ttl, $lease));
    }

    /**
     * Forget a key, so the next run executes again.
     *
     * @throws InvalidIdempotencyKeyException
     */
    public function forget(#[SensitiveParameter] string $key, string $scope): bool
    {
        return $this->manager->forgetIdempotencyKey($key, $scope);
    }
}
