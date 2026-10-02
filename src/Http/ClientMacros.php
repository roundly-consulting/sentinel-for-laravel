<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http;

use Closure;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Str;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Serializer;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Laravel HTTP client macros: `Http::withIdempotencyKey(?string $key = null)` sends
 * `Idempotency-Key: "<key ?? a UUIDv7>"` as an RFC 9651 string.
 *
 * @internal
 */
final class ClientMacros
{
    public static function register(): void
    {
        if (! PendingRequest::hasMacro('withIdempotencyKey')) {
            self::define('withIdempotencyKey', function (?string $key = null): PendingRequest {
                return $this->withHeaders([Settings::idempotencyHeader() => Serializer::bareItem($key ?? (string) Str::uuid7())]);
            });
        }
    }

    /**
     * @param-closure-this PendingRequest $macro
     */
    private static function define(string $name, Closure $macro): void
    {
        PendingRequest::macro($name, $macro);
    }
}
