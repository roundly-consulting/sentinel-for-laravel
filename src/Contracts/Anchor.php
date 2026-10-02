<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Contracts;

use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;

/**
 * An external store for the newest checkpoint of each connection. Built-in drivers: `cache`,
 * `filesystem`, `log`; register more with
 * `Sentinel::extendAnchor('s3-lock', fn (Container $app, array $config): Anchor => …)`.
 *
 * Keep anchors out of reach of whoever can write the database: an anchor is what makes a
 * rollback of the whole database detectable.
 */
interface Anchor
{
    public function name(): string;

    public function publish(AnchorPayload $payload): void;

    /**
     * The newest payload published for the connection; null when there is none — or always,
     * for a write-only anchor (a log).
     */
    public function latest(string $connection): ?AnchorPayload;
}
