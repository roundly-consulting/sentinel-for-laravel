<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Definitions;

use RoundlyConsulting\Sentinel\Contracts\SealDefinition;
use RoundlyConsulting\Sentinel\Definition\SealDefinitionBuilder;

/**
 * A reusable definition: the identity of a party document.
 */
final class PartyIdentitySeal implements SealDefinition
{
    public function define(SealDefinitionBuilder $seal): void
    {
        $seal->attributes('number', 'meta')->plaintext('secret')->strict();
    }
}
