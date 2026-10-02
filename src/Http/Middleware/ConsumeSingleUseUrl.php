<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Middleware;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Routing\UrlGenerator;
use RoundlyConsulting\Sentinel\DataTransferObjects\ConsumeNonceRequest;
use RoundlyConsulting\Sentinel\Exceptions\NonceRejectedException;
use RoundlyConsulting\Sentinel\Nonces\NonceDigest;
use RoundlyConsulting\Sentinel\SentinelManager;
use Symfony\Component\HttpFoundation\Response;

/**
 * `sentinel.single-use` — a URL from `Sentinel::nonces()->signedRoute()` works once: the
 * signature (and expiry) must verify first, then the route's `_nonce` is consumed. Anything
 * else is a generic 403.
 */
final readonly class ConsumeSingleUseUrl
{
    public function __construct(private Container $container) {}

    public function handle(Request $request, Closure $next): Response
    {
        $route = $request->route();
        $name = $route instanceof Route ? $route->getName() : null;
        $nonce = $request->query('_nonce');

        $accepted = $name !== null
            && is_string($nonce)
            && $this->container->make(UrlGenerator::class)->hasValidSignature($request)
            && $this->container->make(SentinelManager::class)->consumeNonce(new ConsumeNonceRequest(NonceDigest::routePurpose($name), $nonce));

        if (! $accepted) {
            throw NonceRejectedException::rejected();
        }

        $response = $next($request);

        return $response instanceof Response ? $response : new Response(is_scalar($response) ? (string) $response : '');
    }
}
