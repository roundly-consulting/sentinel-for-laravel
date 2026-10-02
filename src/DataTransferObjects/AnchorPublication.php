<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

/**
 * Whether one anchor received the newest checkpoint (publication is best effort; a failure
 * is retried by the next checkpoint run).
 */
final readonly class AnchorPublication
{
    public function __construct(
        public string $anchor,
        public bool $published,
        public ?string $error = null,
    ) {}
}
