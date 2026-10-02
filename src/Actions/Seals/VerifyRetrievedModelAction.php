<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
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
 * Reactions: `throw` (report, then `TamperedModelException`), `event` (`TamperDetected` only)
 * or `log` (a warning line only). A partial `select()` is unverifiable and skipped, never a
 * finding. Runs with retrieval verification suspended, so a computed field that loads other
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

        $seals = array_values(array_filter($this->registry->for($model)->all(), static fn (CompiledSeal $seal): bool => $seal->verifiesOnRetrieve));

        if ($seals === []) {
            return;
        }

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

        match ($seal->retrieveReaction ?? Settings::retrieveReaction()) {
            Reaction::Throw => $this->fail($result),
            Reaction::Event => $this->verifier->dispatchTamperDetected($result),
            Reaction::Log => $this->verifier->logFinding($result),
        };
    }

    private function fail(VerificationResult $result): never
    {
        $this->verifier->report($result);

        throw TamperedModelException::forResult($result);
    }
}
