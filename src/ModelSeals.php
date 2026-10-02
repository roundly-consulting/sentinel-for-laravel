<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\CompiledSeals;

/**
 * `Sentinel::model(Invoice::class)` — class-level seal operations.
 */
final readonly class ModelSeals
{
    /**
     * @param  class-string<Model>  $model
     */
    public function __construct(
        private string $model,
        private CompiledSeals $seals,
    ) {}

    public function definition(?string $seal = null): CompiledSeal
    {
        return $this->seals->get($seal);
    }

    /**
     * @return list<string>
     */
    public function seals(): array
    {
        return $this->seals->names();
    }

    /**
     * Rows of the model that have no seal row for the seal (the default unless named).
     *
     * @return Builder<Model>
     */
    public function unsealedQuery(?string $seal = null): Builder
    {
        $name = $this->definition($seal)->name;

        return $this->model::query()->whereDoesntHave('sentinelSeals', static fn (Builder $seals) => $seals->where('seal', $name));
    }
}
