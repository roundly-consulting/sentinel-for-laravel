<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency;

use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;

/**
 * The arguments every programmatic idempotency entry point takes — `run()` / `forget()` on
 * the facade, the manager, the accessor and the actions, and the `Idempotent` job middleware
 * — checked in one place so none accepts what another refuses: a key and a scope of 1–255
 * bytes (an empty scope, e.g. a computed one that came back empty, would merge unrelated
 * callers' keys into one namespace), and a TTL in the range of `idempotency.ttl` and
 * `sentinel.idempotent`.
 *
 * @internal
 */
final class RunLimits
{
    public const int MIN_TTL = 60;

    public const int MAX_TTL = 2592000;

    private const int MAX_LENGTH = 255;

    /**
     * @throws InvalidIdempotencyKeyException
     */
    public static function check(string $key, string $scope, ?int $ttl = null): void
    {
        if ($key === '' || strlen($key) > self::MAX_LENGTH || $scope === '' || strlen($scope) > self::MAX_LENGTH
            || ($ttl !== null && ($ttl < self::MIN_TTL || $ttl > self::MAX_TTL))) {
            throw InvalidIdempotencyKeyException::make();
        }
    }
}
