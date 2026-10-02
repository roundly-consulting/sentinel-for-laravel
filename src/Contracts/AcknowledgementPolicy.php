<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Contracts;

use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgeRequest;

/**
 * Decides whether an actor may acknowledge an out-of-band change. Rebind it to plug in an
 * approval flow. Return null to allow, or a short denial code.
 */
interface AcknowledgementPolicy
{
    public function authorize(AcknowledgeRequest $request): ?string;
}
