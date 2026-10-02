<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http;

use Closure;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Str;
use Psr\Http\Message\RequestInterface;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Serializer;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Laravel HTTP client macros:
 *
 *  - `Http::withSignature(string $keyId, ?SigningOptions $options = null)` signs the request
 *    (RFC 9421) with a key of the outbound ring;
 *  - `Http::withIdempotencyKey(?string $key = null)` sends `Idempotency-Key: "<key ?? a
 *    UUIDv7>"` as an RFC 9651 string.
 *
 * @internal
 */
final class ClientMacros
{
    public static function register(): void
    {
        if (! PendingRequest::hasMacro('withSignature')) {
            self::define('withSignature', function (string $keyId, ?SigningOptions $options = null): PendingRequest {
                // Signs the final PSR-7 request, after every other change to it.
                return $this->withRequestMiddleware(
                    static fn (RequestInterface $request): RequestInterface => app(SentinelManager::class)->signRequest($request, $keyId, $options),
                );
            });
        }

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
