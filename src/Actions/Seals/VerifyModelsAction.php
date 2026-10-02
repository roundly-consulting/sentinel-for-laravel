<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifyManyRequest;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Verify many models (one seal each, or every seal when none is named).
 */
final readonly class VerifyModelsAction
{
    public function __construct(
        private DefinitionRegistry $registry,
        private Verifier $verifier,
    ) {}

    public function execute(VerifyManyRequest $request): VerificationReport
    {
        $results = [];

        foreach ($request->models as $model) {
            $seals = $request->seal === null
                ? $this->registry->for($model)->all()
                : [$this->registry->seal($model, $request->seal)];

            foreach ($seals as $seal) {
                $results[] = $this->verifier->verify($model, $seal, $request->context, Settings::checkLedger());
            }
        }

        return new VerificationReport($results);
    }
}
