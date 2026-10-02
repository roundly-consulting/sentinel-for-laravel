<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Sentinel\Contracts\AcknowledgementPolicy;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgementResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgeRequest;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\ReadBack;
use RoundlyConsulting\Sentinel\Engine\Sealer;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Events\TamperAcknowledged;
use RoundlyConsulting\Sentinel\Exceptions\AcknowledgementDeniedException;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Support\Reasons;
use RoundlyConsulting\Sentinel\Support\Runtime;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Accept an out-of-band change (plan §4.8.1): a required reason, a recorded actor (the system
 * only in the console), the acknowledgement policy (a Gate ability by default) — then re-seal
 * with the previous status and the changed attribute names in the MAC'd ledger entry. An
 * intact model is left untouched.
 */
final readonly class AcknowledgeTamperingAction
{
    public function __construct(
        private DefinitionRegistry $registry,
        private Sealer $sealer,
        private Verifier $verifier,
        private ReadBack $readBack,
        private AcknowledgementPolicy $policy,
        private Runtime $runtime,
        private SealingScope $scope,
        private Dispatcher $events,
    ) {}

    public function execute(AcknowledgeRequest $request): AcknowledgementResult
    {
        $seal = $this->registry->seal($request->model, $request->seal);
        $reason = Reasons::normalize($request->reason);
        $request = new AcknowledgeRequest($request->model, $seal->name, $reason, $this->runtime->actor($request->actor));
        $denial = $this->policy->authorize($request);

        if ($denial !== null) {
            throw AcknowledgementDeniedException::unauthorized($denial);
        }

        $model = $request->model;

        return $this->scope->withoutVerification(fn (): AcknowledgementResult => $model->getConnection()->transaction(function () use ($request, $model, $seal, $reason): AcknowledgementResult {
            $this->readBack->row($model, [], lock: true)
                ?? throw SealingFailedException::rowVanished($model->getMorphClass(), $model->getKey());

            $before = $this->verifier->verify($model, $seal, VerificationContext::Api, Settings::checkLedger(), lock: true);

            if ($before->isIntact()) {
                return new AcknowledgementResult(false, $before);
            }

            $sealed = $this->sealer->seal($model, $seal, SealEvent::Acknowledged, $reason, $request->actor, $before->status, $before->changedAttributes);

            $this->events->dispatch(new TamperAcknowledged(
                $sealed->sealableType, $sealed->sealableId, $seal->name, $sealed->version, $before->status, $before->changedAttributes,
                $reason, $request->actor?->getMorphClass(), $request->actor?->getKey(),
            ));

            return new AcknowledgementResult(true, $before, $sealed);
        }, Settings::transactionAttempts()));
    }
}
