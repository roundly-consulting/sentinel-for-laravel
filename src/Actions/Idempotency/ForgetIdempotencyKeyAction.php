<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Idempotency;

use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\Idempotency\RequestFingerprint;

/**
 * Forget a programmatic idempotency key (`Sentinel::idempotency()->run()`), so the next call
 * runs again. Returns whether the key existed.
 */
final readonly class ForgetIdempotencyKeyAction
{
    public function __construct(private IdempotencyStore $store) {}

    public function execute(string $key, string $scope): bool
    {
        return $this->store->forget(RequestFingerprint::key($scope, 'run', $key));
    }
}
