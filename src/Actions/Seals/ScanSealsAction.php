<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\StatusCount;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Support\BulkQuery;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;
use Throwable;

/**
 * Verify every row of the given models in chunks (soft-deleted rows and rows hidden by
 * global scopes included) — the engine behind `sentinel:verify` — or only the rows a `where`
 * selects (one model). Strict seals report rows that were never sealed. Read-only; every
 * failure is reported as it is found.
 */
final readonly class ScanSealsAction
{
    public function __construct(
        private DefinitionRegistry $registry,
        private Verifier $verifier,
        private SealingScope $scope,
    ) {}

    public function execute(ScanOptions $options): ScanReport
    {
        if ($options->where !== null && count($options->models) !== 1) {
            throw SealingMisconfiguredException::whereNeedsOneModel();
        }

        $state = ['scanned' => 0, 'rows' => 0, 'truncated' => false];
        $counts = [];
        $findings = [];
        $chunk = max(1, $options->chunk);

        $this->scope->withoutVerification(function () use ($options, $chunk, &$state, &$counts, &$findings): void {
            foreach ($options->models as $class) {
                $compiled = $this->registry->for($class);
                $seals = $options->seal === null ? $compiled->all() : [$compiled->get($options->seal)];

                if ($options->checkSchema) {
                    $this->checkSchema($class, $seals);
                }

                $base = $class::query()->withoutGlobalScopes();
                $query = $options->where === null ? $base : BulkQuery::resolve($class, $options->where, $base);

                // The scan's own order (by key, chunk after chunk) — a where filters only.
                $query->reorder()->with('sentinelSeals')->chunkById($chunk, function (Collection $models) use ($options, $seals, &$state, &$counts, &$findings): bool {
                    foreach ($models as $model) {
                        if ($options->limit !== null && $state['rows'] >= $options->limit) {
                            $options->progress?->__invoke((int) $state['rows']);

                            return false;
                        }

                        $state['rows']++;

                        foreach ($seals as $seal) {
                            $result = $this->verify($model, $seal, $options->checkLedger && Settings::checkLedger());
                            $state['scanned']++;
                            $counts[$result->status->value] = ($counts[$result->status->value] ?? 0) + 1;

                            if ($result->failed()) {
                                count($findings) < max(0, $options->maxFindings) ? $findings[] = $result : $state['truncated'] = true;
                            }
                        }
                    }

                    $options->progress?->__invoke((int) $state['rows']);

                    return true;
                });

                if ($options->limit !== null && $state['rows'] >= $options->limit) {
                    break;
                }
            }
        });

        return new ScanReport((int) $state['scanned'], self::counts($counts), $findings, (bool) $state['truncated'], Settings::outdatedIsIntact());
    }

    /**
     * One row's verdict. Whatever a row holds — an edited seal row, data a computed field's
     * closure chokes on — is that row's finding (`Unverifiable(error)`, reported like any
     * other), never the end of the scan that must still find every other row.
     */
    private function verify(Model $model, CompiledSeal $seal, bool $checkLedger): VerificationResult
    {
        try {
            return $this->verifier->verify($model, $seal, VerificationContext::Command, $checkLedger);
        } catch (Throwable $exception) {
            report($exception);

            $result = new VerificationResult(
                VerificationStatus::Unverifiable, 'error', $model->getMorphClass(), $model->getKey(), $seal->name,
                context: VerificationContext::Command, outdatedIsIntact: Settings::outdatedIsIntact(),
            );
            $this->verifier->report($result);

            return $result;
        }
    }

    /**
     * @param  class-string<Model>  $class
     * @param  list<CompiledSeal>  $seals
     */
    private function checkSchema(string $class, array $seals): void
    {
        $model = new $class;
        $schema = $model->getConnection()->getSchemaBuilder();

        foreach ($seals as $seal) {
            foreach ($seal->columns() as $column) {
                if (! $schema->hasColumn($model->getTable(), $column)) {
                    throw SealingMisconfiguredException::missingColumn($class, $seal->name, $column);
                }
            }
        }
    }

    /**
     * @param  array<string, int>  $counts
     * @return list<StatusCount>
     */
    private static function counts(array $counts): array
    {
        $list = [];

        foreach (VerificationStatus::cases() as $status) {
            if (isset($counts[$status->value])) {
                $list[] = new StatusCount($status, $counts[$status->value]);
            }
        }

        return $list;
    }
}
