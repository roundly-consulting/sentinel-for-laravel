<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;

/**
 * Verify one seal of a model — the input of `VerifyModelAction` (`Sentinel::verify()`). A null
 * seal is the model's default seal; `context` records the entry point on findings.
 */
final readonly class VerifyRequest
{
    public function __construct(
        public Model $model,
        public ?string $seal = null,
        public bool $checkLedger = true,
        public VerificationContext $context = VerificationContext::Api,
    ) {}
}
