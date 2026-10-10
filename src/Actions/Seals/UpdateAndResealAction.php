<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\UpdateAndResealRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\Sealer;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Support\BulkQuery;
use RoundlyConsulting\Sentinel\Support\Identifiers;
use RoundlyConsulting\Sentinel\Support\Reasons;
use RoundlyConsulting\Sentinel\Support\Runtime;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * The deliberate mass update (plan §4.8.3). Every selected row must verify intact first — a
 * single non-intact row and nothing at all is written (`TamperedModelException::many`).
 * Then, chunk by chunk in one transaction each: lock the rows, verify them again under the
 * lock, run the query-builder update, and re-seal each row with the reason (event
 * `resealed`). A row that turns non-intact between the two passes rolls its chunk back.
 */
final readonly class UpdateAndResealAction
{
    public function __construct(
        private DefinitionRegistry $registry,
        private Verifier $verifier,
        private Sealer $sealer,
        private Runtime $runtime,
        private SealingScope $scope,
    ) {}

    public function execute(UpdateAndResealRequest $request): ResealReport
    {
        foreach (array_keys($request->values) as $column) {
            if (! Identifiers::isColumn($column)) {
                throw SealingMisconfiguredException::invalidColumn($column);
            }
        }

        $seals = $this->registry->for($request->model)->all();
        $reason = Reasons::normalize($request->reason);
        $actor = $this->runtime->actor($request->actor);
        $query = BulkQuery::resolve($request->model, $request->query);
        $chunk = max(1, $request->chunk);

        return $this->scope->withoutVerification(function () use ($request, $seals, $reason, $actor, $query, $chunk): ResealReport {
            $ids = $this->verifyAll($query, $seals, $chunk);
            $updated = 0;

            foreach (array_chunk($ids, $chunk) as $batch) {
                $updated += $query->getModel()->getConnection()->transaction(
                    fn (): int => $this->updateBatch($request, $query, $batch, $seals, $reason, $actor),
                    Settings::transactionAttempts(),
                );
            }

            return new ResealReport(resealed: $updated);
        });
    }

    /**
     * Pass 1, read-only: the keys of every selected row, all of them intact.
     *
     * @param  Builder<Model>  $query
     * @param  list<CompiledSeal>  $seals
     * @return list<int|string>
     */
    private function verifyAll(Builder $query, array $seals, int $chunk): array
    {
        $ids = [];
        $failures = [];

        // Paged by key: a caller's order would stay the primary sort and skip or repeat rows.
        $query->clone()->reorder()->chunkById($chunk, function (Collection $models) use ($seals, &$ids, &$failures): void {
            foreach ($models as $model) {
                $ids[] = $model->getKey();
                array_push($failures, ...$this->failures($model, $seals, false));
            }
        });

        if ($failures !== []) {
            throw TamperedModelException::many($failures);
        }

        return $ids;
    }

    /**
     * @param  Builder<Model>  $query
     * @param  list<int|string>  $ids
     * @param  list<CompiledSeal>  $seals
     */
    private function updateBatch(UpdateAndResealRequest $request, Builder $query, array $ids, array $seals, string $reason, ?Model $actor): int
    {
        $models = $query->clone()->whereKey($ids)->lockForUpdate()->get();
        $failures = [];
        $sealed = [];

        foreach ($models as $model) {
            foreach ($seals as $seal) {
                $verdict = $this->verifier->verify($model, $seal, VerificationContext::Write, Settings::checkLedger(), lock: true);
                $verdict->failed() ? $failures[] = $verdict : $sealed[] = [$model, $seal, $verdict->status];
            }
        }

        if ($failures !== []) {
            throw TamperedModelException::many($failures);
        }

        if ($models->isEmpty()) {
            return 0;
        }

        $request->model::query()->withoutGlobalScopes()->whereKey($models->modelKeys())->update($request->values);

        foreach ($sealed as [$model, $seal, $status]) {
            // A lenient seal that was never made stays unmade.
            if ($status !== VerificationStatus::Unsealed) {
                $this->sealer->seal($model, $seal, SealEvent::Resealed, $reason, $actor, $status === VerificationStatus::Outdated ? $status : null);
            }
        }

        return $models->count();
    }

    /**
     * @param  list<CompiledSeal>  $seals
     * @return list<VerificationResult>
     */
    private function failures(Model $model, array $seals, bool $lock): array
    {
        $failures = [];

        foreach ($seals as $seal) {
            $verdict = $this->verifier->verify($model, $seal, VerificationContext::Api, Settings::checkLedger(), $lock);

            if ($verdict->failed()) {
                $failures[] = $verdict;
            }
        }

        return $failures;
    }
}
