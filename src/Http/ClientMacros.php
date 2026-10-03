<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http;

use Closure;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Request as ClientRequest;
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
 *    (RFC 9421) with a key of the outbound ring — as it is finally sent, after every request
 *    middleware and before-sending callback, whenever they were added (a retry or a redirect
 *    is signed afresh);
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
                $sign = static fn (ClientRequest $request): RequestInterface => app(SentinelManager::class)->signRequest($request->toPsrRequest(), $keyId, $options);

                // Signing must be the last change to the request: the before-sending callbacks
                // run after every request middleware, and before each send this moves the
                // signer behind any callback registered after withSignature().
                $this->beforeSending($sign);

                return $this->withRequestMiddleware(function (RequestInterface $request) use ($sign): RequestInterface {
                    $this->beforeSendingCallbacks = $this->beforeSendingCallbacks
                        ->reject(static fn (mixed $callback): bool => $callback === $sign)
                        ->push($sign)
                        ->values();

                    return $request;
                });
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
