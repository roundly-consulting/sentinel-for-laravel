<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use RoundlyConsulting\Sentinel\DataTransferObjects\UnsealRequest;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\ReadBack;
use RoundlyConsulting\Sentinel\Engine\Sealer;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Support\Reasons;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Deliberately remove a model's seal (plan §4.8.6): the seal row goes and an `unsealed`
 * tombstone records the reason, actor and the status it had. Afterwards the model verifies as
 * `unsealed` (lenient seal) or `missing` (strict). Returns whether a seal row existed.
 */
final readonly class UnsealModelAction
{
    public function __construct(
        private DefinitionRegistry $registry,
        private Sealer $sealer,
        private Verifier $verifier,
        private ReadBack $readBack,
    ) {}

    public function execute(UnsealRequest $request): bool
    {
        $model = $request->model;
        $seal = $this->registry->seal($model, $request->seal);
        $reason = Reasons::normalize($request->reason);

        return $model->getConnection()->transaction(function () use ($request, $model, $seal, $reason): bool {
            $this->readBack->row($model, [], lock: true)
                ?? throw SealingFailedException::rowVanished($model->getMorphClass(), $model->getKey());

            $before = $this->verifier->verify($model, $seal, VerificationContext::Api, Settings::checkLedger(), lock: true);

            return $this->sealer->tombstone($model, $seal, SealEvent::Unsealed, $before->status, $reason, $request->actor);
        }, Settings::transactionAttempts());
    }
}
