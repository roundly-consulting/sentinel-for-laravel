<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Accessors;

use Closure;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentCall;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentResult;
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
     * Run the callback once per (key, scope); a repeat returns the stored result.
     */
    public function run(#[SensitiveParameter] string $key, string $scope, Closure $callback, ?string $fingerprint = null, ?int $ttl = null): IdempotentResult
    {
        return $this->manager->runIdempotent(new IdempotentCall($key, $scope, $callback, $fingerprint, $ttl));
    }

    /**
     * Forget a key, so the next run executes again.
     */
    public function forget(#[SensitiveParameter] string $key, string $scope): bool
    {
        return $this->manager->forgetIdempotencyKey($key, $scope);
    }
}
