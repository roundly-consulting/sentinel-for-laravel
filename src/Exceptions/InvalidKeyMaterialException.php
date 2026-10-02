<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use RoundlyConsulting\Sentinel\Enums\Algorithm;
use Throwable;

/**
 * Key material that cannot back the algorithm it claims. Messages never contain material.
 */
final class InvalidKeyMaterialException extends SentinelException
{
    public static function encodingRequired(): self
    {
        return new self('Key material must be encoded as "base64:<standard base64>"; raw strings (passphrases) are refused.');
    }

    public static function malformedEncoding(): self
    {
        return new self('Key material after "base64:" is not canonical, padded standard base64.');
    }

    public static function tooShort(Algorithm $algorithm, int $minimum): self
    {
        return new self("The {$algorithm->value} key material must be at least {$minimum} random bytes.");
    }

    public static function tooLong(Algorithm $algorithm, int $maximum): self
    {
        return new self("The {$algorithm->value} key material must be at most {$maximum} bytes.");
    }

    public static function weakSecret(Algorithm $algorithm): self
    {
        return new self("The {$algorithm->value} secret is a single repeated byte; generate it with `php artisan sentinel:key:generate`.");
    }

    public static function curveMismatch(Algorithm $algorithm): self
    {
        return new self("The EC key's curve does not match {$algorithm->value}.");
    }

    public static function wrongType(Algorithm $algorithm, string $detail, ?Throwable $previous = null): self
    {
        return new self("The key material is not a valid {$algorithm->value} key: {$detail}.", previous: $previous);
    }

    public static function unsupported(Algorithm $algorithm, ?Throwable $previous = null): self
    {
        return new self("The {$algorithm->value} algorithm is not available on this PHP build (ext-sodium is required for ed25519).", previous: $previous);
    }

    public static function publicOnly(string $ring, string $keyId): self
    {
        return new self("The key [{$ring}:{$keyId}] holds only public material and cannot sign.");
    }
}
