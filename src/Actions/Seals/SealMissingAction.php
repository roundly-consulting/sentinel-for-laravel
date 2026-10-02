<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\DataTransferObjects\BaselineOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\ReadBack;
use RoundlyConsulting\Sentinel\Engine\Sealer;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\Support\Reasons;
use RoundlyConsulting\Sentinel\Support\Runtime;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Support\Tables;

/**
 * Adoption (plan §4.8.5): seal rows that have never been sealed — no seal row **and** no
 * ledger history — with event `baseline` and a required reason. A row whose history shows a
 * seal that went missing (or was deliberately unsealed) is reported, never baselined: that
 * would launder a deletion.
 */
final readonly class SealMissingAction
{
    private const int MAX_REPORTED = 1000;

    public function __construct(
        private DefinitionRegistry $registry,
        private Sealer $sealer,
        private Verifier $verifier,
        private ReadBack $readBack,
        private Runtime $runtime,
        private SealingScope $scope,
    ) {}

    public function execute(BaselineOptions $options): ResealReport
    {
        $compiled = $this->registry->for($options->model);
        $seals = $options->seal === null ? $compiled->all() : [$compiled->get($options->seal)];
        $reason = Reasons::normalize($options->reason);
        $actor = $this->runtime->actor($options->actor);
        $tally = ['resealed' => 0, 'skipped' => 0, 'failed' => 0];
        $skipped = [];

        $this->scope->withoutVerification(function () use ($options, $seals, $reason, $actor, &$tally, &$skipped): void {
            foreach ($seals as $seal) {
                $options->model::query()->withoutGlobalScopes()
                    ->whereDoesntHave('sentinelSeals', static fn (Builder $rows) => $rows->where('seal', $seal->name))
                    ->chunkById(max(1, $options->chunk), function (Collection $models) use ($seal, $reason, $actor, &$tally, &$skipped): void {
                        foreach ($models as $model) {
                            $outcome = $this->baseline($model, $seal, $reason, $actor);

                            if ($outcome instanceof VerificationResult) {
                                $tally['skipped']++;

                                if (count($skipped) < self::MAX_REPORTED) {
                                    $skipped[] = $outcome;
                                }
                            } elseif ($outcome !== null) {
                                $tally[$outcome]++;
                            }
                        }
                    });
            }
        });

        return new ResealReport(resealed: $tally['resealed'], skipped: $tally['skipped'], failed: $tally['failed'], skippedResults: $skipped);
    }

    /**
     * @return 'resealed'|'failed'|VerificationResult|null null = sealed concurrently
     */
    private function baseline(Model $model, CompiledSeal $seal, string $reason, ?Model $actor): string|VerificationResult|null
    {
        try {
            return $model->getConnection()->transaction(function () use ($model, $seal, $reason, $actor): string|VerificationResult|null {
                $this->readBack->row($model, [], lock: true)
                    ?? throw SealingFailedException::rowVanished($model->getMorphClass(), $model->getKey());

                if (Tables::seals($model, $seal->name)->lockForUpdate()->exists()) {
                    return null;
                }

                if ($this->sealer->head($model, $seal->name) !== null) {
                    return $this->verifier->verify($model, $seal, VerificationContext::Command, Settings::checkLedger(), lock: true);
                }

                $this->sealer->seal($model, $seal, SealEvent::Baseline, $reason, $actor);

                return 'resealed';
            }, Settings::transactionAttempts());
        } catch (SentinelException) {
            return 'failed';
        }
    }
}
