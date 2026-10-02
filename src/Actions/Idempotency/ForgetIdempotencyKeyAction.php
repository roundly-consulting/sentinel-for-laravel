<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Idempotency;

use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;
use RoundlyConsulting\Sentinel\Idempotency\RequestFingerprint;
use RoundlyConsulting\Sentinel\Idempotency\RunLimits;

/**
 * Forget a programmatic idempotency key (`Sentinel::idempotency()->run()`), so the next call
 * runs again. Returns whether the key existed. Takes the key and scope `run()` takes.
 */
final readonly class ForgetIdempotencyKeyAction
{
    public function __construct(private IdempotencyStore $store) {}

    /**
     * @throws InvalidIdempotencyKeyException for an empty or overlong key or scope
     */
    public function execute(string $key, string $scope): bool
    {
        RunLimits::check($key, $scope);

        return $this->store->forget(RequestFingerprint::key($scope, 'run', $key));
    }
}
