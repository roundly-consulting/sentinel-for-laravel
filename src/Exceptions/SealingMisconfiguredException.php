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

    /**
     * MAC keys are shared with peers by design, so they live in a ring of their own: a peer
     * holding a seal or ledger ring's secret could derive its subkeys, and a MAC over a
     * signature base would be a valid HTTP signature.
     */
    public static function notAMacRing(string $ring): self
    {
        $shown = preg_match('/^[a-z0-9_-]{1,64}$/D', $ring) === 1 ? $ring : '(invalid)';

        return new self("Key ring [{$shown}] cannot hold MAC keys: seals, the ledger or HTTP message signatures use it. Configure a ring of its own under sentinel.keys.rings.");
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

    /**
     * The second line of the save()/delete() guard: a write that reached Eloquent's insert,
     * update or delete with model events muted (saveQuietly(), deleteQuietly(),
     * withoutEvents()), where the saving / deleting listeners never run.
     */
    public static function writeOutsideSealedPath(string $class): self
    {
        return new self("[{$class}] was written outside the sealed write path — an override of save() or delete() that skips it, reached with model events muted; call \$this->persistSealed(fn () => parent::save(...)) from the override.");
    }

    /**
     * A sealed row is verified and sealed under its key: re-keying it would verify the new id
     * while writing the old one, and orphan its seal and history.
     */
    public static function keyChanged(string $class): self
    {
        return new self("[{$class}] cannot change the primary key of a sealed row; create a new row instead.");
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
