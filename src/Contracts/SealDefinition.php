<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Contracts;

use RoundlyConsulting\Sentinel\Definition\SealDefinitionBuilder;

/**
 * A reusable seal definition, applied with `->using(PartyIdentitySeal::class)`; inline calls
 * on the same seal win. Resolved from the container once, at compile time.
 */
interface SealDefinition
{
    public function define(SealDefinitionBuilder $seal): void;
}
