<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency;

use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;

/**
 * The arguments every programmatic idempotency entry point takes — `run()` / `forget()` on
 * the facade, the manager, the accessor and the actions, and the `Idempotent` job middleware
 * — checked in one place so none accepts what another refuses: a key and a scope of 1–255
 * bytes (an empty scope, e.g. a computed one that came back empty, would merge unrelated
 * callers' keys into one namespace), a TTL in the range of `idempotency.ttl` and
 * `sentinel.idempotent`, and a lease of 1–86 400 seconds.
 *
 * @internal
 */
final class RunLimits
{
    public const int MIN_TTL = 60;

    public const int MAX_TTL = 2592000;

    /** A lease longer than a day protects nothing a queue would still deliver. */
    public const int MAX_LEASE = 86400;

    private const int MAX_LENGTH = 255;

    /**
     * @throws InvalidIdempotencyKeyException
     */
    public static function check(string $key, string $scope, ?int $ttl = null, ?int $lease = null): void
    {
        if ($key === '' || strlen($key) > self::MAX_LENGTH || $scope === '' || strlen($scope) > self::MAX_LENGTH
            || ($ttl !== null && ($ttl < self::MIN_TTL || $ttl > self::MAX_TTL))
            || ($lease !== null && ($lease < 1 || $lease > self::MAX_LEASE))) {
            throw InvalidIdempotencyKeyException::make();
        }
    }
}
