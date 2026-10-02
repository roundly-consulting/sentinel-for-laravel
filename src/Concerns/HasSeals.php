<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Concerns;

use Closure;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgementResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Enums\PersistOperation;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\SealingScope;

/**
 * Seals on an Eloquent model (implement `Sealable` alongside). Every Eloquent write path —
 * save, update, create, touch, push, restore, increment/decrement, delete, forceDelete, and
 * their quiet variants — runs through `SentinelManager::persist()`, which writes and seals in
 * one transaction. Everything here delegates to the manager (never an action), so
 * `Sentinel::fake()` sees it.
 *
 * Reserved names: seal, verifySeal, verifySealOrFail, isIntact, acknowledgeTampering,
 * persistSealed, sentinelSeals, and the scopes whereSealed / whereNotSealed / withSeals.
 *
 * @mixin Model
 *
 * @phpstan-require-extends Model
 */
trait HasSeals
{
    /**
     * A `saving` / `deleting` guard: every Eloquent save and delete of the model must run
     * inside `persistSealed()` — HasSeals' own save() and delete() do, and so does an override
     * that calls `persistSealed()` or (in a subclass) `parent::save()`. An override that skips
     * it is refused before anything is written. Every retrieved model passes the manager's
     * verify-on-retrieve hook (a no-op unless a seal declares verifyOnRetrieve()).
     */
    public static function bootHasSeals(): void
    {
        static::saving(static function (Model $model): void {
            if (! app(SealingScope::class)->isWriting($model)) {
                throw SealingMisconfiguredException::saveOverridden($model::class, 'save');
            }
        });

        static::deleting(static function (Model $model): void {
            if (! app(SealingScope::class)->isWriting($model)) {
                throw SealingMisconfiguredException::saveOverridden($model::class, 'delete');
            }
        });

        static::retrieved(static function (Model $model): void {
            app(SentinelManager::class)->retrieved($model);
        });
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public function save(array $options = []): bool
    {
        return $this->persistSealed(fn (): bool => parent::save($options)) === true;
    }

    public function delete(): ?bool
    {
        $deleted = $this->persistSealed(fn (): ?bool => parent::delete(), PersistOperation::Delete);

        return is_bool($deleted) ? $deleted : null;
    }

    /**
     * The sealed write path. A host that must override save() / delete() in the class using
     * this trait wraps the parent call — `return $this->persistSealed(fn () => parent::save($options));`
     * — while a subclass simply calls `parent::save($options)`.
     */
    public function persistSealed(Closure $write, PersistOperation $operation = PersistOperation::Save): mixed
    {
        return app(SealingScope::class)->writing($this, fn (): mixed => app(SentinelManager::class)->persist($this, $write, $operation));
    }

    /**
     * @return MorphMany<Seal, $this>
     */
    public function sentinelSeals(): MorphMany
    {
        return $this->morphMany(Seal::class, 'sealable');
    }

    public function seal(?string $seal = null): SealResult
    {
        return app(SentinelManager::class)->seal($this, $seal);
    }

    public function verifySeal(?string $seal = null): VerificationResult
    {
        return app(SentinelManager::class)->verify($this, $seal);
    }

    public function verifySealOrFail(?string $seal = null): VerificationResult
    {
        return app(SentinelManager::class)->verifyOrFail($this, $seal);
    }

    /**
     * Every seal of the model is intact.
     */
    public function isIntact(): bool
    {
        return app(SentinelManager::class)->isIntact($this);
    }

    public function acknowledgeTampering(string $reason, ?Model $actor = null, ?string $seal = null): AcknowledgementResult
    {
        return app(SentinelManager::class)->acknowledge($this, $reason, $actor, $seal);
    }

    /**
     * Rows that have a seal row (the default seal unless named).
     *
     * @param  Builder<static>  $query
     */
    public function scopeWhereSealed(Builder $query, ?string $seal = null): void
    {
        $name = app(SentinelManager::class)->model(static::class)->definition($seal)->name;

        $query->whereHas('sentinelSeals', static fn (Builder $seals) => $seals->where('seal', $name));
    }

    /**
     * Rows without a seal row (the default seal unless named).
     *
     * @param  Builder<static>  $query
     */
    public function scopeWhereNotSealed(Builder $query, ?string $seal = null): void
    {
        $name = app(SentinelManager::class)->model(static::class)->definition($seal)->name;

        $query->whereDoesntHave('sentinelSeals', static fn (Builder $seals) => $seals->where('seal', $name));
    }

    /**
     * Eager-load the seal rows.
     *
     * @param  Builder<static>  $query
     */
    public function scopeWithSeals(Builder $query): void
    {
        $query->with('sentinelSeals');
    }

    /**
     * @param  string  $column
     * @param  float|int  $amount
     * @param  array<string, mixed>  $extra
     * @param  string  $method
     * @return int|false
     */
    protected function incrementOrDecrement($column, $amount, $extra, $method)
    {
        return $this->persistSealed(
            fn () => parent::incrementOrDecrement($column, $amount, $extra, $method),
            PersistOperation::Increment,
        );
    }

    /**
     * Laravel 13+ (`incrementEach` / `decrementEach`).
     *
     * @param  array<string, float|int>  $columns
     * @param  array<string, mixed>  $extra
     * @return int|false
     */
    protected function incrementOrDecrementEach(array $columns, array $extra, string $method)
    {
        return $this->persistSealed(
            fn () => parent::incrementOrDecrementEach($columns, $extra, $method),
            PersistOperation::Increment,
        );
    }
}
