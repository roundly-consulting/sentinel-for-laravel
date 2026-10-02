<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;

/**
 * @internal built by the manager for `VerifyModelsAction` (null seal = every seal)
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
