<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Testing;

use Illuminate\Container\Container;

/**
 * Use in a host test case (`uses(TestCase::class, WithSentinelKeys::class)->in('Feature')`):
 * before each test every config ring without a key gets a fresh HMAC test key, so sealable
 * factories seal for real. Laravel runs `setUpWithSentinelKeys()` itself.
 */
trait WithSentinelKeys
{
    protected function setUpWithSentinelKeys(): void
    {
        SentinelTestKeys::install(Container::getInstance());
    }
}
