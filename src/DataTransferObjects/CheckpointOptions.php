<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

/**
 * One checkpoint batch: the connection (null = the default) and how many pending ledger
 * entries to fold in (null = `sentinel.ledger.batch_size`).
 */
final readonly class CheckpointOptions
{
    public function __construct(
        public ?string $connection = null,
        public ?int $batchSize = null,
    ) {}
}
