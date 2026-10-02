<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * Sentinel was asked to work with something that is not set up for it: an unconfigured key
 * ring, a model that is not sealable, a seal that is not declared.
 */
final class SealingMisconfiguredException extends SentinelException
{
    public static function unknownRing(string $ring): self
    {
        $shown = preg_match('/^[a-z0-9_-]{1,64}$/D', $ring) === 1 ? $ring : '(invalid)';

        return new self("Key ring [{$shown}] is not configured under sentinel.keys.rings.");
    }

    public static function notSealable(string $class): self
    {
        return new self("[{$class}] is not sealable: it must implement RoundlyConsulting\\Sentinel\\Contracts\\Sealable and use RoundlyConsulting\\Sentinel\\Concerns\\HasSeals.");
    }

    /**
     * @param  list<string>  $declared  the seal names the model declares (code-defined)
     */
    public static function unknownSeal(string $class, string $seal, array $declared = []): self
    {
        $shown = preg_match('/^[a-z0-9_.-]{1,64}$/D', $seal) === 1 ? $seal : '(invalid)';

        return new self("[{$class}] declares no seal [{$shown}]".($declared === [] ? '.' : '; declared: '.implode(', ', $declared).'.'));
    }

    public static function saveOverridden(string $class, string $method): self
    {
        return new self("[{$class}] overrides {$method}() without sealing; call \$this->persistSealed(fn () => parent::{$method}(...)) from the override.");
    }

    public static function middlewareParameter(string $parameter): self
    {
        $shown = preg_match('/^[A-Za-z0-9_]{1,64}$/D', $parameter) === 1 ? $parameter : '(invalid)';

        return new self("sentinel.verified names the route parameter [{$shown}], which is not a bound sealable model; route-model binding must run first.");
    }

    public static function bindingsNotSubstituted(string $parameter): self
    {
        $shown = preg_match('/^[A-Za-z0-9_]{1,64}$/D', $parameter) === 1 ? $parameter : '(invalid)';

        return new self("sentinel.verified ran before route-model binding: the sealable route parameter [{$shown}] is not a model yet. Declare it inside the web/api group (after SubstituteBindings).");
    }

    public static function queryModelMismatch(string $expected, string $given): self
    {
        return new self("The query selects [{$given}] models, not [{$expected}].");
    }

    public static function missingColumn(string $class, string $seal, string $column): self
    {
        return new self("Seal [{$seal}] of [{$class}] covers the column [{$column}], which its table does not have.");
    }

    public static function unknownModel(string $model): self
    {
        $shown = preg_match('/^[A-Za-z0-9_\\\\.:-]{1,255}$/D', $model) === 1 ? $model : '(invalid)';

        return new self("[{$shown}] is not a model class or morph alias.");
    }

    public static function whereNeedsOneModel(): self
    {
        return new self('A scan narrowed with `where` must scan exactly one model class.');
    }

    public static function invalidColumn(string $column): self
    {
        $shown = preg_match('/^[A-Za-z0-9_.]{1,64}$/D', $column) === 1 ? $column : '(invalid)';

        return new self("[{$shown}] is not a column name a mass update may set.");
    }

    public static function middlewareOption(string $middleware, string $option): self
    {
        $shown = preg_match('/^[A-Za-z0-9_.:-]{1,64}$/D', $option) === 1 ? $option : '(invalid)';

        return new self("[{$shown}] is not a valid option of the {$middleware} middleware.");
    }
}
