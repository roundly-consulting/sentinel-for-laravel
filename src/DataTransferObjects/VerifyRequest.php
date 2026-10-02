<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;

/**
 * @internal built by the manager for `VerifyModelAction`
 */
final readonly class VerifyRequest
{
    public function __construct(
        public Model $model,
        public string $seal,
        public bool $checkLedger = true,
        public VerificationContext $context = VerificationContext::Api,
    ) {}
}
