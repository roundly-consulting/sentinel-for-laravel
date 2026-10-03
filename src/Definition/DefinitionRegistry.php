<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Definition;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use ReflectionFunction;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Contracts\SealDefinition;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSealDefinitionException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Support\Identifiers;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Compiles `defineSeals()` once per model class and keeps the immutable result (plan §9.1).
 * A singleton: the compiled definitions derive from code only, so keeping them across Octane
 * requests is safe — which is also why every closure must be `static`.
 *
 * @internal
 */
final class DefinitionRegistry
{
    /** @var array<class-string, CompiledSeals> */
    private array $compiled = [];

    public function __construct(private readonly Container $container) {}

    /**
     * @param  class-string|Model  $model
     *
     * @throws SealingMisconfiguredException when the model is not sealable
     * @throws InvalidSealDefinitionException listing every problem of its definition
     */
    public function for(string|Model $model): CompiledSeals
    {
        $class = is_string($model) ? $model : $model::class;

        return $this->compiled[$class] ??= $this->compile($class);
    }

    public function seal(Model $model, ?string $seal = null): CompiledSeal
    {
        return $this->for($model)->get($seal);
    }

    /**
     * @param  class-string  $class
     */
    private function compile(string $class): CompiledSeals
    {
        if (! is_subclass_of($class, Model::class) || ! is_subclass_of($class, Sealable::class) || ! in_array(HasSeals::class, class_uses_recursive($class), true)) {
            throw SealingMisconfiguredException::notSealable($class);
        }

        $builder = new SealBuilder;
        $class::defineSeals($builder);

        $model = new $class;
        $casts = $model->getCasts();
        $problems = [];
        $seals = [];

        if ($builder->declared() === []) {
            $problems[] = 'it declares no seals';
        }

        foreach ($builder->declared() as $declared) {
            $name = $declared->name();

            if (! Identifiers::isSeal($name)) {
                $problems[] = "the seal name [{$name}] is invalid; use [a-z][a-z0-9_.-]{0,63}";

                continue;
            }

            if (isset($seals[$name])) {
                $problems[] = "the seal [{$name}] is declared twice";

                continue;
            }

            $definition = $this->resolve($declared, $problems);
            $compiled = $this->compileSeal($class, $definition, $model->getKeyName(), $casts, $problems);

            if ($compiled !== null) {
                $seals[$name] = $compiled;
            }
        }

        if ($problems !== []) {
            throw InvalidSealDefinitionException::forClass($class, $problems);
        }

        return new CompiledSeals($class, $seals, (string) array_key_first($seals));
    }

    /**
     * Apply a `using()` definition class underneath the inline declaration.
     *
     * @param  list<string>  $problems
     */
    private function resolve(SealDefinitionBuilder $declared, array &$problems): SealDefinitionBuilder
    {
        $using = $declared->usedDefinition();

        if ($using === null) {
            return $declared;
        }

        $definition = class_exists($using) ? $this->container->make($using) : null;

        if (! $definition instanceof SealDefinition) {
            $problems[] = "seal [{$declared->name()}] uses [{$using}], which is not a SealDefinition";

            return $declared;
        }

        $base = new SealDefinitionBuilder($declared->name());
        $definition->define($base);

        return $declared->over($base);
    }

    /**
     * @param  class-string  $class
     * @param  array<string, string>  $casts
     * @param  list<string>  $problems
     */
    private function compileSeal(string $class, SealDefinitionBuilder $definition, string $keyName, array $casts, array &$problems): ?CompiledSeal
    {
        $name = $definition->name();
        $before = count($problems);
        array_push($problems, ...$definition->problems());

        $fields = [];

        foreach ($definition->declaredAttributes() as $column => $type) {
            if (! Identifiers::isColumn($column)) {
                $problems[] = "seal [{$name}] lists an invalid column [{$column}]";

                continue;
            }

            if ($column === $keyName) {
                $problems[] = "seal [{$name}] lists the primary key [{$column}]; it is already bound as the document id";

                continue;
            }

            $type ??= Inference::fromCast($casts[$column] ?? null);

            if ($type === null) {
                $problems[] = "seal [{$name}] field [a:{$column}] is cast to a float or an out-of-range decimal; declare float('{$column}', scale) or decimal('{$column}', scale)";

                continue;
            }

            $fields[] = ManifestField::attribute($column, $type);
        }

        foreach ($definition->declaredComputed() as $computedName => $computed) {
            if (! Identifiers::isComputed($computedName)) {
                $problems[] = "seal [{$name}] declares an invalid computed name [{$computedName}]";

                continue;
            }

            $this->assertStatic($computed->resolver, "seal [{$name}] computed field [c:{$computedName}]", $problems);
            $fields[] = ManifestField::computed($computedName, $computed->type ?? SealType::auto(), $computed->resolver);
        }

        if ($fields === [] && count($problems) === $before) {
            $problems[] = "seal [{$name}] has no fields";
        }

        $scope = $definition->declaredScope();

        if ($scope !== null) {
            $this->assertStatic($scope, "seal [{$name}] scope", $problems);
        }

        $ring = $definition->declaredRing() ?? Settings::defaultRing();
        $algorithms = $this->algorithms($name, $ring, $definition->declaredAlgorithms(), $problems);

        // A partner's key — or a secret a partner knows — must never vouch for a seal.
        if (in_array($ring, Settings::signatureRings(), true)) {
            $problems[] = "seal [{$name}] uses the ring [{$ring}], which HTTP message signatures use";
        }

        foreach ($definition->declaredAcceptRings() as $accepted) {
            if ($accepted === $ring) {
                $problems[] = "seal [{$name}] lists its own ring [{$ring}] in acceptRings()";
            } elseif (! in_array($accepted, Settings::rings(), true)) {
                $problems[] = "seal [{$name}] accepts the unknown ring [{$accepted}]";
            } elseif (in_array($accepted, Settings::signatureRings(), true)) {
                $problems[] = "seal [{$name}] accepts the ring [{$accepted}], which HTTP message signatures use";
            }
        }

        if (count($problems) !== $before || $algorithms === null) {
            return null;
        }

        usort($fields, static fn (ManifestField $a, ManifestField $b): int => strcmp($a->name, $b->name));

        return new CompiledSeal(
            $class, $name, $fields, $ring, $definition->declaredAcceptRings(), $algorithms, $definition->isStrict(),
            $definition->isAuto(), $definition->verifiesOnRetrieve(), $definition->retrieveReaction(),
            $definition->declaredFieldTags(), $scope, $definition->declaredPolicy(),
        );
    }

    /**
     * The seal's algorithms: its declaration ∩ the ring's allow-list (the ring's list when
     * nothing is declared).
     *
     * @param  list<Algorithm>|null  $declared
     * @param  list<string>  $problems
     * @return list<Algorithm>|null
     */
    private function algorithms(string $name, string $ring, ?array $declared, array &$problems): ?array
    {
        if (! in_array($ring, Settings::rings(), true)) {
            $problems[] = "seal [{$name}] uses the unknown ring [{$ring}]";

            return null;
        }

        $allowed = Settings::ring($ring)->algorithms;

        if ($declared === null) {
            return $allowed;
        }

        if ($declared === []) {
            $problems[] = "seal [{$name}] allows no algorithm";

            return null;
        }

        foreach ($declared as $algorithm) {
            if (! in_array($algorithm, $allowed, true)) {
                $problems[] = "seal [{$name}] allows [{$algorithm->value}], which ring [{$ring}] does not";
            }
        }

        $unique = [];

        foreach ($declared as $algorithm) {
            $unique[$algorithm->value] = $algorithm;
        }

        return array_values($unique);
    }

    /**
     * Closures kept in the singleton registry must not capture `$this` (request state).
     *
     * @param  list<string>  $problems
     */
    private function assertStatic(Closure $closure, string $what, array &$problems): void
    {
        if ((new ReflectionFunction($closure))->getClosureThis() !== null) {
            $problems[] = "{$what} must be a static closure (static fn …)";
        }
    }
}
