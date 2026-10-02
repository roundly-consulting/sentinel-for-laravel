<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Accessors;

use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * `Sentinel::keys()` — key rings and their keys. Every call goes through the manager, so
 * `Sentinel::fake()` sees it.
 */
final readonly class KeysAccessor
{
    public function __construct(private SentinelManager $manager) {}

    /**
     * A ring handle (null = `sentinel.keys.default_ring`).
     */
    public function ring(?string $ring = null): KeyRingHandle
    {
        $ring ??= Settings::defaultRing();
        Settings::ring($ring);

        return new KeyRingHandle($this->manager, $ring);
    }

    /**
     * Every key of every ring — never material.
     *
     * @return list<KeyInfo>
     */
    public function all(): array
    {
        return $this->manager->listKeys();
    }

    /**
     * @return list<string>
     */
    public function rings(): array
    {
        return Settings::rings();
    }
}
