<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

/**
 * An anchor did not accept the newest checkpoint (dispatched synchronously). The next
 * checkpoint run publishes again.
 */
final readonly class AnchorPublishFailed
{
    public function __construct(
        public string $anchor,
        public string $connection,
        public int $seq,
        public string $error,
    ) {}
}
