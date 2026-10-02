<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\StatusCount;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Verify every row of the given models in chunks (soft-deleted rows and rows hidden by
 * global scopes included) — the engine behind `sentinel:verify`. Strict seals report rows
 * that were never sealed. Read-only; every failure is reported as it is found.
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

                $class::query()->withoutGlobalScopes()->with('sentinelSeals')->chunkById($chunk, function (Collection $models) use ($options, $seals, &$state, &$counts, &$findings): bool {
                    foreach ($models as $model) {
                        if ($options->limit !== null && $state['rows'] >= $options->limit) {
                            return false;
                        }

                        $state['rows']++;

                        foreach ($seals as $seal) {
                            $result = $this->verifier->verify($model, $seal, VerificationContext::Command, $options->checkLedger && Settings::checkLedger());
                            $state['scanned']++;
                            $counts[$result->status->value] = ($counts[$result->status->value] ?? 0) + 1;

                            if ($result->failed()) {
                                count($findings) < max(0, $options->maxFindings) ? $findings[] = $result : $state['truncated'] = true;
                            }
                        }
                    }

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
