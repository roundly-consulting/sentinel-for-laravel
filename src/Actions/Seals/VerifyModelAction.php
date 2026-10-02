<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifyRequest;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Verify one seal of a model against the database as it is now.
 */
final readonly class VerifyModelAction
{
    public function __construct(
        private DefinitionRegistry $registry,
        private Verifier $verifier,
    ) {}

    public function execute(VerifyRequest $request): VerificationResult
    {
        return $this->verifier->verify(
            $request->model,
            $this->registry->seal($request->model, $request->seal),
            $request->context,
            $request->checkLedger && Settings::checkLedger(),
        );
    }
}
