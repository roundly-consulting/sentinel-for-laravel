<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Verify-on-retrieve (the `retrieved` hook of `HasSeals`): every seal declared
 * `verifyOnRetrieve()` is checked against the values the model was just loaded with.
 *
 * Every finding is reported — `TamperDetected` and a warning log line, as for any
 * verification — and the `throw` reaction then refuses to load the model
 * (`TamperedModelException`); `report` lets it load. A partial `select()` of the seal's own
 * columns is unverifiable and skipped, never a finding. Runs with retrieval verification suspended, so a computed field that loads other
 * sealed models cannot recurse.
 *
 * @internal
 */
final readonly class VerifyRetrievedModelAction
{
    public function __construct(
        private DefinitionRegistry $registry,
        private Verifier $verifier,
        private SealingScope $scope,
    ) {}

    public function execute(Model $model): void
    {
        if ($this->scope->verificationSuspended()) {
            return;
        }

        // HasSeals hooks only classes that declare a retrieve seal (I-5); the filter keeps the
        // others' seals out.
        $seals = array_values(array_filter($this->registry->for($model)->all(), static fn (CompiledSeal $seal): bool => $seal->verifiesOnRetrieve));

        $this->scope->withoutVerification(function () use ($model, $seals): void {
            foreach ($seals as $seal) {
                $this->check($model, $seal);
            }
        });
    }

    private function check(Model $model, CompiledSeal $seal): void
    {
        $result = $this->verifier->verify(
            $model, $seal, VerificationContext::Retrieve, Settings::retrieveChecksLedger() && Settings::checkLedger(), report: false,
        );

        if ($result->isIntact() || ($result->status === VerificationStatus::Unverifiable && $result->reason === 'missing_attribute')) {
            return;
        }

        $this->verifier->report($result);

        if (($seal->retrieveReaction ?? Settings::retrieveReaction()) === Reaction::Throw) {
            throw TamperedModelException::forResult($result);
        }
    }
}
