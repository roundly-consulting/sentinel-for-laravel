<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use RoundlyConsulting\Sentinel\Enums\Algorithm;

/**
 * An algorithm outside the allow-list of a seal or ring, or a name that is no algorithm at
 * all (`none`, `HS256`, `rsa-*`). Algorithm agility never comes from stored or received
 * data, so this is always a configuration error.
 */
final class AlgorithmNotAllowedException extends SentinelException
{
    public static function forSeal(string $model, string $seal, Algorithm $algorithm): self
    {
        return new self("The algorithm [{$algorithm->value}] is not allowed for seal [{$seal}] on [{$model}].");
    }

    public static function forRing(string $ring, Algorithm $algorithm): self
    {
        return new self("The algorithm [{$algorithm->value}] is not allowed in key ring [{$ring}].");
    }

    public static function unknownName(string $name, string $where): self
    {
        $shown = preg_match('/^[A-Za-z0-9._-]{1,64}$/D', $name) === 1 ? $name : '(invalid)';

        return new self("The algorithm name [{$shown}] in [{$where}] is not supported; use one of: "
            .implode(', ', array_map(static fn (Algorithm $a): string => $a->value, Algorithm::cases())).'.');
    }
}
