<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\KeyTypes;

use RoundlyConsulting\Sentinel\Tests\TestCase;

/**
 * Sealables keyed by UUIDs, actors by bigints (D45): the morph columns follow `key_type`.
 */
abstract class UuidKeyTestCase extends TestCase
{
    /** @return array<string, mixed> */
    protected function configBeforeBoot(): array
    {
        return [...parent::configBeforeBoot(), 'sentinel.key_type' => 'uuid'];
    }
}
