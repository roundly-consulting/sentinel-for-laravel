<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use RoundlyConsulting\Sentinel\Contracts\IdempotencyScopeResolver;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\Http\Middleware\VerifyHttpSignature;

/**
 * The default idempotency scope: `user:<guard>:<id>` for an authenticated user, else
 * `sig:<ring>:<keyid>` for a request a verified HTTP signature vouches for, else
 * `ip:<address>` (TrustProxies-aware). Place `sentinel.idempotent` after `auth` so the user
 * is known.
 */
final readonly class RequestScope implements IdempotencyScopeResolver
{
    public function __construct(private Container $container) {}

    public function resolve(Request $request): string
    {
        $user = $request->user();

        if ($user instanceof Authenticatable) {
            $guard = $this->container->bound('auth') ? $this->container->make('auth')->getDefaultDriver() : 'web';

            return 'user:'.$guard.':'.(string) $user->getAuthIdentifier();
        }

        $signature = $request->attributes->get(VerifyHttpSignature::ATTRIBUTE);

        if ($signature instanceof VerifiedSignature) {
            return 'sig:'.$signature->ring.':'.$signature->keyId;
        }

        return 'ip:'.($request->ip() ?? 'unknown');
    }

    /**
     * The route identity a key is bound to: the route name, else `METHOD uri-pattern`.
     */
    public static function route(Request $request): string
    {
        $route = $request->route();

        if (! $route instanceof Route) {
            return strtoupper($request->getMethod()).' '.$request->getPathInfo();
        }

        return $route->getName() ?? strtoupper($request->getMethod()).' '.$route->uri();
    }
}
