<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgeRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\ReadBack;
use RoundlyConsulting\Sentinel\Engine\Sealer;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\AcknowledgementDeniedException;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Support\Reasons;
use RoundlyConsulting\Sentinel\Support\Runtime;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Re-seal a model's rows with the ring's current key (rotation, changed definitions) — event
 * `rotated` in the ledger. Re-sealing never launders (D44): only rows that verify intact or
 * outdated are re-sealed, each re-verified under its row lock first; every other status is
 * skipped and reported — or acknowledged (reason + actor recorded) when an acknowledgement
 * reason is given. Rows already sealed by the current key with the current definition are
 * left alone; lenient rows without a seal are adopted by `sealMissing()`, not here.
 */
final readonly class ResealModelsAction
{
    private const int MAX_REPORTED = 1000;

    public function __construct(
        private DefinitionRegistry $registry,
        private Verifier $verifier,
        private Sealer $sealer,
        private ReadBack $readBack,
        private KeyStoreManager $keys,
        private SealingScope $scope,
        private AcknowledgeTamperingAction $acknowledge,
        private Runtime $runtime,
    ) {}

    public function execute(ResealOptions $options): ResealReport
    {
        $compiled = $this->registry->for($options->model);
        $seals = $options->seal === null ? $compiled->all() : [$compiled->get($options->seal)];
        $reason = $options->acknowledgeReason === null ? null : Reasons::normalize($options->acknowledgeReason);
        $actor = $reason === null ? $options->actor : $this->runtime->actor($options->actor);
        $current = [];

        foreach ($seals as $seal) {
            $current[$seal->name] = $this->keys->signingKey($seal->ring)->keyId;
        }

        $tally = ['resealed' => 0, 'acknowledged' => 0, 'skipped' => 0, 'failed' => 0];
        $skipped = [];
        $processed = 0;

        $this->scope->withoutVerification(function () use ($options, $seals, $reason, $actor, $current, &$tally, &$skipped, &$processed): void {
            $options->model::query()->withoutGlobalScopes()->with('sentinelSeals')->chunkById(
                max(1, $options->chunk),
                function (Collection $models) use ($options, $seals, $reason, $actor, $current, &$tally, &$skipped, &$processed): void {
                    foreach ($models as $model) {
                        $processed++;

                        foreach ($seals as $seal) {
                            $outcome = $this->one($model, $seal, $options, $reason, $actor, $current[$seal->name]);

                            if ($outcome instanceof VerificationResult) {
                                $tally['skipped']++;

                                if (count($skipped) < self::MAX_REPORTED) {
                                    $skipped[] = $outcome;
                                }
                            } elseif ($outcome !== null) {
                                $tally[$outcome]++;
                            }
                        }
                    }

                    $options->progress?->__invoke($processed);
                },
            );
        });

        return new ResealReport($tally['resealed'], $tally['acknowledged'], $tally['skipped'], $tally['failed'], $skipped, $options->dryRun);
    }

    /**
     * @return 'resealed'|'acknowledged'|'failed'|VerificationResult|null null = not in scope
     */
    private function one(Model $model, CompiledSeal $seal, ResealOptions $options, ?string $reason, ?Model $actor, string $currentKeyId): string|VerificationResult|null
    {
        $verdict = $this->verifier->verify($model, $seal, VerificationContext::Command, Settings::checkLedger(), report: false);

        if ($verdict->status === VerificationStatus::Unsealed || ($options->fromKeyId !== null && $verdict->keyId !== $options->fromKeyId)) {
            return null;
        }

        if (self::rotatable($verdict)) {
            $upToDate = $verdict->status === VerificationStatus::Intact && $verdict->keyId === $currentKeyId;

            if ($options->upgradeFormat || $upToDate || ($options->onlyOutdated && $verdict->status !== VerificationStatus::Outdated)) {
                return null;
            }

            return $options->dryRun ? 'resealed' : $this->rotate($model, $seal, $actor);
        }

        if ($reason === null) {
            $this->verifier->report($verdict);

            return $verdict;
        }

        if ($options->dryRun) {
            return 'acknowledged';
        }

        try {
            return $this->acknowledge->execute(new AcknowledgeRequest($model, $seal->name, $reason, $actor))->acknowledged ? 'acknowledged' : null;
        } catch (AcknowledgementDeniedException $exception) {
            throw $exception;
        } catch (SentinelException) {
            return 'failed';
        }
    }

    /**
     * Re-verify under the row lock (a concurrent out-of-band change must not be laundered),
     * then re-seal with the current key.
     *
     * @return 'resealed'|'failed'|VerificationResult
     */
    private function rotate(Model $model, CompiledSeal $seal, ?Model $actor): string|VerificationResult
    {
        try {
            return $model->getConnection()->transaction(function () use ($model, $seal, $actor): string|VerificationResult {
                $this->readBack->row($model, [], lock: true)
                    ?? throw SealingFailedException::rowVanished($model->getMorphClass(), $model->getKey());

                $verdict = $this->verifier->verify($model, $seal, VerificationContext::Command, Settings::checkLedger(), lock: true);

                if (! self::rotatable($verdict)) {
                    return $verdict;
                }

                $this->sealer->seal($model, $seal, SealEvent::Rotated, actor: $actor, previousStatus: $verdict->status === VerificationStatus::Outdated ? VerificationStatus::Outdated : null);

                return 'resealed';
            }, Settings::transactionAttempts());
        } catch (SentinelException) {
            return 'failed';
        }
    }

    private static function rotatable(VerificationResult $verdict): bool
    {
        return $verdict->status === VerificationStatus::Intact || $verdict->status === VerificationStatus::Outdated;
    }
}
