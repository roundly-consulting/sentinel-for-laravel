<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Middleware;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use RoundlyConsulting\Sentinel\Contracts\IdempotencyScopeResolver;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\Enums\IdempotencyOutcome;
use RoundlyConsulting\Sentinel\Events\IdempotencyRejected;
use RoundlyConsulting\Sentinel\Events\IdempotentRequestReplayed;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyKeyMissingException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyKeyReusedException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyRequestInProgressException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotentResponseUnavailableException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Idempotency\KeyParser;
use RoundlyConsulting\Sentinel\Idempotency\ReleaseResponse;
use RoundlyConsulting\Sentinel\Idempotency\RequestFingerprint;
use RoundlyConsulting\Sentinel\Idempotency\RequestScope;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Settings;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * `sentinel.idempotent[:optional|required[,ttl]]` — the `Idempotency-Key` header
 * (draft-ietf-httpapi-idempotency-key-header-07) on POST and PATCH (`idempotency.methods`).
 *
 * Order of checks: method → header (400) → scope + fingerprint → own the key (else replay,
 * 409 + Retry-After, or 422) → handler → store the response (or release the key on 5xx and
 * on a throwable). Place it after `auth`, so the key is scoped to the user.
 */
final readonly class EnsureIdempotency
{
    public function __construct(private Container $container) {}

    /**
     * The middleware accepting requests without a key: `->middleware(EnsureIdempotency::optional())`.
     *
     * @throws SealingMisconfiguredException for a TTL outside 60–2 592 000 seconds
     */
    public static function optional(?int $ttl = null): string
    {
        return self::with('optional', $ttl);
    }

    /**
     * The middleware refusing requests without a key (400): `->middleware(EnsureIdempotency::required(ttl: 3600))`.
     *
     * @throws SealingMisconfiguredException for a TTL outside 60–2 592 000 seconds
     */
    public static function required(?int $ttl = null): string
    {
        return self::with('required', $ttl);
    }

    private static function with(string $mode, ?int $ttl): string
    {
        return self::class.':'.$mode.($ttl === null ? '' : ','.self::ttl((string) $ttl));
    }

    public function handle(Request $request, Closure $next, string $mode = 'optional', ?string $ttl = null): Response
    {
        if (! in_array(strtoupper($request->getMethod()), Settings::idempotencyMethods(), true)) {
            return self::response($next($request));
        }

        $required = match ($mode) {
            'required' => true,
            'optional' => false,
            default => throw SealingMisconfiguredException::middlewareOption('sentinel.idempotent', $mode),
        };

        $ttl = $ttl === null ? Settings::idempotencyTtl() : self::ttl($ttl);

        try {
            $key = KeyParser::fromRequest($request) ?? ($required ? throw IdempotencyKeyMissingException::make() : null);
        } catch (IdempotencyException $exception) {
            throw $this->rejected($request, $exception);
        }

        if ($key === null) {
            return self::response($next($request));
        }

        $scope = $this->container->make(IdempotencyScopeResolver::class)->resolve($request);
        $idempotent = new IdempotentRequest(RequestFingerprint::key($scope, RequestScope::route($request), $key), $scope, RequestFingerprint::request($request), $ttl);
        $manager = $this->container->make(SentinelManager::class);
        $decision = $manager->beginIdempotentRequest($idempotent);

        if ($decision->outcome === IdempotencyOutcome::Replay && $decision->replay !== null) {
            $this->container->make(Dispatcher::class)->dispatch(new IdempotentRequestReplayed($request->getMethod(), RequestScope::route($request), $decision->replay->status));

            return $decision->replay->toResponse(Settings::replayHeader());
        }

        if ($decision->outcome !== IdempotencyOutcome::Proceed || $decision->ownerToken === null) {
            throw $this->rejected($request, match ($decision->outcome) {
                IdempotencyOutcome::Reused => IdempotencyKeyReusedException::make(),
                IdempotencyOutcome::InProgress => IdempotencyRequestInProgressException::retryAfter($decision->retryAfter ?? 1),
                default => IdempotentResponseUnavailableException::make(),
            });
        }

        $owned = $idempotent->ownedBy($decision->ownerToken);

        return Settings::idempotencyTransactional()
            ? $this->transactional($request, $next, $owned, $manager)
            : $this->run($request, $next, $owned, $manager);
    }

    private function run(Request $request, Closure $next, IdempotentRequest $owned, SentinelManager $manager): Response
    {
        try {
            $response = self::response($next($request));
        } catch (Throwable $exception) {
            $manager->releaseIdempotentRequest($owned);

            throw $exception;
        }

        if (! self::storable($response)) {
            $manager->releaseIdempotentRequest($owned);

            return $response;
        }

        $manager->completeIdempotentRequest($owned, $response);

        return $response;
    }

    /**
     * The handler and the idempotency record commit together (exactly once for the writes on
     * `database.connection`): a response that is not stored rolls the handler's writes back,
     * and so does a lease lost to another request meanwhile.
     */
    private function transactional(Request $request, Closure $next, IdempotentRequest $owned, SentinelManager $manager): Response
    {
        try {
            return (new IdempotencyKey)->getConnection()->transaction(function () use ($request, $next, $owned, $manager): Response {
                $response = self::response($next($request));

                if (! self::storable($response)) {
                    throw new ReleaseResponse($response);
                }

                if (! $manager->completeIdempotentRequest($owned, $response)) {
                    throw new ReleaseResponse(IdempotencyRequestInProgressException::retryAfter(1)->toResponse($request), release: false);
                }

                return $response;
            });
        } catch (ReleaseResponse $signal) {
            if ($signal->release) {
                $manager->releaseIdempotentRequest($owned);
            }

            return $signal->response;
        } catch (Throwable $exception) {
            $manager->releaseIdempotentRequest($owned);

            throw $exception;
        }
    }

    private function rejected(Request $request, IdempotencyException $exception): IdempotencyException
    {
        $this->container->make(Dispatcher::class)->dispatch(new IdempotencyRejected(
            $request->getMethod(), RequestScope::route($request), $exception->getStatusCode(), $exception->rejection(),
        ));

        return $exception;
    }

    /**
     * 5xx is released (the client may retry) unless `store_server_errors`; 4xx is stored
     * unless `store_client_errors` is off.
     */
    private static function storable(Response $response): bool
    {
        $status = $response->getStatusCode();

        return match (true) {
            $status >= 500 => Settings::storesServerErrors(),
            $status >= 400 => Settings::storesClientErrors(),
            default => true,
        };
    }

    private static function ttl(string $ttl): int
    {
        if (preg_match('/^\d{2,7}$/D', $ttl) !== 1 || (int) $ttl < 60 || (int) $ttl > 2592000) {
            throw SealingMisconfiguredException::middlewareOption('sentinel.idempotent', $ttl);
        }

        return (int) $ttl;
    }

    private static function response(mixed $response): Response
    {
        return $response instanceof Response ? $response : new Response(is_scalar($response) ? (string) $response : '');
    }
}
