<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use RoundlyConsulting\Sentinel\DataTransferObjects\SealRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealResult;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\Persister;
use RoundlyConsulting\Sentinel\Engine\ReadBack;
use RoundlyConsulting\Sentinel\Engine\Sealer;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Seal a model explicitly (`Sentinel::for($model)->seal()`), e.g. after a computed field's
 * source rows changed. Never launders: a model changed outside the application must be
 * acknowledged instead — only intact, outdated, never-sealed and (lenient) unsealed models and
 * proven computed-only drift are (re-)sealed, and drift is recorded in the ledger. A strict seal
 * that was deliberately unsealed comes back through an acknowledgement, never through seal().
 */
final readonly class SealModelAction
{
    public function __construct(
        private DefinitionRegistry $registry,
        private Sealer $sealer,
        private Verifier $verifier,
        private ReadBack $readBack,
    ) {}

    public function execute(SealRequest $request): SealResult
    {
        $model = $request->model;
        $seal = $this->registry->seal($model, $request->seal);

        if (! $model->exists) {
            throw SealingFailedException::notPersisted($model->getMorphClass());
        }

        return $model->getConnection()->transaction(function () use ($request, $model, $seal): SealResult {
            $this->readBack->row($model, [], lock: true)
                ?? throw SealingFailedException::rowVanished($model->getMorphClass(), $model->getKey());

            $verdict = $this->verifier->verify($model, $seal, VerificationContext::Api, Settings::checkLedger(), lock: true);
            $absent = $verdict->status === VerificationStatus::Unsealed
                || ($verdict->status === VerificationStatus::Missing && $verdict->reason === 'never_sealed');

            if (! $absent && ! Persister::benign($verdict)) {
                throw TamperedModelException::forResult($verdict);
            }

            return $this->sealer->seal(
                $model, $seal, $absent ? SealEvent::Sealed : SealEvent::Resealed, $request->reason, $request->actor,
                $verdict->isIntact() ? null : $verdict->status,
                $verdict->onlyComputedChanged() ? $verdict->changedAttributes : null,
            );
        }, Settings::transactionAttempts());
    }
}
