<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel;

use Closure;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\DataTransferObjects\BaselineOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealWhereRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\UpdateAndResealRequest;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\CompiledSeals;

/**
 * `Sentinel::model(Invoice::class)` — class-level seal operations: scans, re-sealing, bulk
 * acknowledgement, deliberate mass updates and adoption. Every call goes through the
 * manager, so `Sentinel::fake()` sees it; queries over another model class are refused.
 */
final readonly class ModelSeals
{
    /**
     * @param  class-string<Model>  $model
     */
    public function __construct(
        private SentinelManager $manager,
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
     * Verify every row — or only those `where` selects: a closure receiving the model's query
     * (global scopes off), or a builder of this model — in chunks (one seal, or every seal
     * when null). `progress` receives the rows processed so far after each chunk.
     *
     * @param  (Closure(Builder<Model>): mixed)|Builder<Model>|null  $where
     * @param  (Closure(int): void)|null  $progress
     */
    public function scan(
        ?string $seal = null,
        int $chunk = 500,
        bool $checkLedger = true,
        Closure|Builder|null $where = null,
        ?int $limit = null,
        int $maxFindings = 1000,
        ?Closure $progress = null,
    ): ScanReport {
        return $this->manager->scan(new ScanOptions([$this->model], $this->name($seal), $chunk, $checkLedger, $limit, $maxFindings, where: $where, progress: $progress));
    }

    /**
     * Re-seal intact/outdated rows with the current key; other rows are skipped and reported
     * — or acknowledged with `acknowledgeReason`.
     *
     * @param  (Closure(int): void)|null  $progress
     */
    public function reseal(
        ?string $seal = null,
        bool $onlyOutdated = false,
        ?string $fromKeyId = null,
        int $chunk = 500,
        bool $dryRun = false,
        ?string $acknowledgeReason = null,
        ?Model $actor = null,
        ?Closure $progress = null,
    ): ResealReport {
        return $this->manager->reseal(new ResealOptions($this->model, $this->name($seal), $fromKeyId, $onlyOutdated, $chunk, $dryRun, $acknowledgeReason, $actor, progress: $progress));
    }

    /**
     * Acknowledge every row the query selects.
     *
     * @param  (Closure(Builder<Model>): mixed)|Builder<Model>  $query
     */
    public function resealWhere(Closure|Builder $query, string $reason, ?Model $actor = null, ?string $seal = null, int $chunk = 500): ResealReport
    {
        return $this->manager->resealWhere(new ResealWhereRequest($this->model, $query, $reason, $actor, $this->name($seal), $chunk));
    }

    /**
     * A deliberate mass update: verify every selected row, update, re-seal with the reason.
     *
     * @param  (Closure(Builder<Model>): mixed)|Builder<Model>  $query
     * @param  array<string, mixed>  $values
     */
    public function updateAndReseal(Closure|Builder $query, array $values, string $reason, ?Model $actor = null, int $chunk = 500): ResealReport
    {
        return $this->manager->updateAndReseal(new UpdateAndResealRequest($this->model, $query, $values, $reason, $actor, $chunk));
    }

    /**
     * Seal rows that were never sealed (no seal row, no ledger history).
     *
     * @param  (Closure(int): void)|null  $progress
     */
    public function sealMissing(string $reason, ?string $seal = null, int $chunk = 500, ?Model $actor = null, ?Closure $progress = null): ResealReport
    {
        return $this->manager->sealMissing(new BaselineOptions($this->model, $this->name($seal), $reason, $chunk, $actor, $progress));
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

    private function name(?string $seal): ?string
    {
        return $seal === null ? null : $this->definition($seal)->name;
    }
}
