<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use RoundlyConsulting\Sentinel\Contracts\AcknowledgementPolicy;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgeRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\UnsealRequest;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\ReadBack;
use RoundlyConsulting\Sentinel\Engine\Sealer;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Exceptions\AcknowledgementDeniedException;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Support\Reasons;
use RoundlyConsulting\Sentinel\Support\Runtime;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Deliberately remove a model's seal (plan §4.8.6): the seal row goes and an `unsealed`
 * tombstone records the reason, actor and the status it had. Afterwards the model verifies as
 * `unsealed` (lenient seal) or `missing` (strict). Returns whether a seal row existed.
 *
 * Removing a seal is as strong as accepting a change — a lenient seal is re-sealed by its next
 * write — so it runs the same checks as an acknowledgement: a required reason, a recorded actor
 * (the system only in the console) and the acknowledgement policy (a Gate ability by default).
 */
final readonly class UnsealModelAction
{
    public function __construct(
        private DefinitionRegistry $registry,
        private Sealer $sealer,
        private Verifier $verifier,
        private ReadBack $readBack,
        private AcknowledgementPolicy $policy,
        private Runtime $runtime,
    ) {}

    public function execute(UnsealRequest $request): bool
    {
        $model = $request->model;
        $seal = $this->registry->seal($model, $request->seal);
        $reason = Reasons::normalize($request->reason);
        $actor = $this->runtime->actor($request->actor);
        $denial = $this->policy->authorize(new AcknowledgeRequest($model, $seal->name, $reason, $actor));

        if ($denial !== null) {
            throw AcknowledgementDeniedException::unauthorized($denial);
        }

        return $model->getConnection()->transaction(function () use ($actor, $model, $seal, $reason): bool {
            $this->readBack->row($model, [], lock: true)
                ?? throw SealingFailedException::rowVanished($model->getMorphClass(), $model->getKey());

            $before = $this->verifier->verify($model, $seal, VerificationContext::Api, Settings::checkLedger(), lock: true);

            return $this->sealer->tombstone($model, $seal, SealEvent::Unsealed, $before->status, $reason, $actor);
        }, Settings::transactionAttempts());
    }
}
