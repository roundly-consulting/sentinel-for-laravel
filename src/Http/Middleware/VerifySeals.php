<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Middleware;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use ReflectionNamedType;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Http\Exceptions\SealVerificationFailedHttpException;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Settings;
use Symfony\Component\HttpFoundation\Response;

/**
 * `sentinel.verified` — verify the route's sealed models before the action runs.
 *
 *  - `sentinel.verified` — every route parameter that is a sealable model, every seal;
 *  - `sentinel.verified:invoice@financial,customer` — the named parameters (and seals).
 *
 * A model that is not intact aborts with a generic `verified_status` response (or, with
 * `verified_reaction = report`, is only reported). A named parameter that is not a bound
 * sealable model, or a sealable parameter that route-model binding has not resolved yet,
 * fails closed — declare the middleware inside the web/api group (after SubstituteBindings).
 */
final readonly class VerifySeals
{
    public function __construct(private Container $container) {}

    public function handle(Request $request, Closure $next, string ...$parameters): Response
    {
        $route = $request->route();
        $manager = $this->container->make(SentinelManager::class);

        foreach ($parameters === [] ? $this->everySealable($route) : $this->named($route, array_values($parameters)) as [$model, $seal]) {
            $results = $seal === null
                ? $manager->verifyManyIn(VerificationContext::Middleware, [$model])->results
                : [$manager->verifyIn(VerificationContext::Middleware, $model, $seal)];

            $this->react($results);
        }

        $response = $next($request);

        return $response instanceof Response ? $response : new Response((string) $response);
    }

    /**
     * @param  list<VerificationResult>  $results
     */
    private function react(array $results): void
    {
        foreach ($results as $result) {
            // `report`: the verifier already fired TamperDetected and logged the finding.
            if ($result->failed() && Settings::verifiedAborts()) {
                throw SealVerificationFailedHttpException::forFinding(TamperedModelException::forResult($result));
            }
        }
    }

    /**
     * @return list<array{0: Model, 1: null}>
     */
    private function everySealable(mixed $route): array
    {
        if (! $route instanceof Route) {
            return [];
        }

        $this->assertBound($route);
        $models = [];

        foreach ($route->parameters() as $value) {
            if ($value instanceof Model && $value instanceof Sealable) {
                $models[] = [$value, null];
            }
        }

        return $models;
    }

    /**
     * @param  list<string>  $parameters
     * @return list<array{0: Model, 1: string|null}>
     */
    private function named(mixed $route, array $parameters): array
    {
        $models = [];

        foreach ($parameters as $parameter) {
            [$name, $seal] = array_pad(explode('@', trim($parameter), 2), 2, null);
            $value = $route instanceof Route ? $route->parameter((string) $name) : null;

            if (! $value instanceof Model || ! $value instanceof Sealable) {
                throw SealingMisconfiguredException::middlewareParameter((string) $name);
            }

            $models[] = [$value, $seal === null || $seal === '' ? null : $seal];
        }

        return $models;
    }

    /**
     * A sealable type-hinted action parameter that is still a raw id means route-model binding
     * has not run: verifying "every sealable" would silently verify nothing.
     */
    private function assertBound(Route $route): void
    {
        foreach ($route->signatureParameters(['subClass' => Model::class]) as $parameter) {
            $type = $parameter->getType();
            $class = $type instanceof ReflectionNamedType ? $type->getName() : null;
            $value = $route->parameter($parameter->getName());

            if ($class !== null && is_subclass_of($class, Sealable::class) && $value !== null && ! $value instanceof Model) {
                throw SealingMisconfiguredException::bindingsNotSubstituted($parameter->getName());
            }
        }
    }
}
