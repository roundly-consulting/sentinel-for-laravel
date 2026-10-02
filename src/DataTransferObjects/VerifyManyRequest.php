<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;

/**
 * Verify many models — the input of `VerifyModelsAction` (`Sentinel::verifyMany()`): one seal
 * each, or every declared seal when `seal` is null.
 */
final readonly class VerifyManyRequest
{
    /**
     * @param  iterable<Model>  $models
     */
    public function __construct(
        public iterable $models,
        public ?string $seal = null,
        public VerificationContext $context = VerificationContext::Api,
    ) {}
}
