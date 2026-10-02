<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Anchors;

use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Sentinel\Contracts\Anchor;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Ledger\AnchorCodec;
use RuntimeException;

/**
 * An in-memory anchor a test can read, corrupt or take offline.
 */
final class MemoryAnchor implements Anchor
{
    /** @var array<string, string> */
    public array $stored = [];

    public bool $broken = false;

    /**
     * Register a fresh one as the `memory` driver and configure it as the only anchor.
     */
    public static function install(): self
    {
        $anchor = new self;
        Sentinel::extendAnchor('memory', static fn (Container $app, array $config): Anchor => $anchor);
        config()->set('sentinel.ledger.anchors', 'memory');

        return $anchor;
    }

    public function name(): string
    {
        return 'memory';
    }

    public function publish(AnchorPayload $payload): void
    {
        if ($this->broken) {
            throw new RuntimeException('anchor offline');
        }

        $this->stored[$payload->connection] = AnchorCodec::encode($payload);
    }

    public function latest(string $connection): ?AnchorPayload
    {
        if ($this->broken) {
            throw new RuntimeException('anchor offline');
        }

        return isset($this->stored[$connection]) ? AnchorCodec::decode($this->stored[$connection]) : null;
    }
}
