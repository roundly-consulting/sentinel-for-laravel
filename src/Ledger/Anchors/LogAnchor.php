<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Ledger\Anchors;

use Psr\Log\LoggerInterface;
use RoundlyConsulting\Sentinel\Contracts\Anchor;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;
use RoundlyConsulting\Sentinel\Ledger\AnchorCodec;

/**
 * Write-only: every checkpoint as an info line (`sentinel.anchor`) on a log channel shipped
 * elsewhere. Compare one later with `sentinel:verify --ledger --anchor='<payload json>'`.
 *
 * @internal
 */
final readonly class LogAnchor implements Anchor
{
    public function __construct(private LoggerInterface $logger) {}

    public function name(): string
    {
        return 'log';
    }

    public function publish(AnchorPayload $payload): void
    {
        $this->logger->info('sentinel.anchor', ['payload' => AnchorCodec::encode($payload), ...AnchorCodec::toArray($payload)]);
    }

    public function latest(string $connection): ?AnchorPayload
    {
        return null;
    }
}
