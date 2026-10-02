<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Concerns;

use Closure;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use ReflectionMethod;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgementResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Enums\PersistOperation;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\SentinelManager;

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
     * A model that overrides save() or delete() must route the write through
     * `persistSealed()`, or its writes would skip sealing.
     */
    public static function bootHasSeals(): void
    {
        foreach (['save', 'delete'] as $method) {
            $declared = new ReflectionMethod(static::class, $method);

            // __TRAIT__, not self::class: inside a trait, self is the class using it.
            if ($declared->getFileName() === (new ReflectionMethod(__TRAIT__, $method))->getFileName()) {
                continue;
            }

            $lines = array_slice(file((string) $declared->getFileName()) ?: [], (int) $declared->getStartLine() - 1, (int) $declared->getEndLine() - (int) $declared->getStartLine() + 1);

            if (! str_contains(implode('', $lines), 'persistSealed(')) {
                throw SealingMisconfiguredException::saveOverridden(static::class, $method);
            }
        }
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public function save(array $options = []): bool
    {
        return app(SentinelManager::class)->persist($this, fn (): bool => parent::save($options), PersistOperation::Save) === true;
    }

    public function delete(): ?bool
    {
        $deleted = app(SentinelManager::class)->persist($this, fn (): ?bool => parent::delete(), PersistOperation::Delete);

        return is_bool($deleted) ? $deleted : null;
    }

    /**
     * For a host that must override save() / delete(): wrap the parent call so it stays
     * sealed — `return $this->persistSealed(fn () => parent::save($options));`.
     */
    public function persistSealed(Closure $write, PersistOperation $operation = PersistOperation::Save): mixed
    {
        return app(SentinelManager::class)->persist($this, $write, $operation);
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
        return app(SentinelManager::class)->persist(
            $this,
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
        return app(SentinelManager::class)->persist(
            $this,
            fn () => parent::incrementOrDecrementEach($columns, $extra, $method),
            PersistOperation::Increment,
        );
    }
}
