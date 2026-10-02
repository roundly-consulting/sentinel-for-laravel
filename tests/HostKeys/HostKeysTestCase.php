<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\HostKeys;

use RoundlyConsulting\Sentinel\Testing\WithSentinelKeys;
use RoundlyConsulting\Sentinel\Tests\TestCase;

/**
 * A host's test case: no Sentinel key in its environment, `WithSentinelKeys` instead (I-4).
 */
abstract class HostKeysTestCase extends TestCase
{
    use WithSentinelKeys;

    /** @return array<string, mixed> */
    protected function configBeforeBoot(): array
    {
        return [...parent::configBeforeBoot(), 'sentinel.keys.rings.default.key_id' => null, 'sentinel.keys.rings.default.key' => null];
    }
}
