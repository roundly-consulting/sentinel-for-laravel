<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Accessors;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointRecord;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerRecord;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerVerifyOptions;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * `Sentinel::ledger()` — checkpoints, anchors and ledger verification. Every call goes
 * through the manager, so `Sentinel::fake()` sees it.
 */
final readonly class LedgerAccessor
{
    public function __construct(private SentinelManager $manager) {}

    /**
     * Fold the next batch of pending entries into a checkpoint (null = nothing pending).
     */
    public function checkpoint(?string $connection = null): ?CheckpointResult
    {
        return $this->manager->checkpoint(new CheckpointOptions($connection));
    }

    /**
     * Verify checkpoints, anchors, pending entries and (optionally) every entity's ledger head;
     * null = every connection in `sentinel.ledger.connections`.
     */
    public function verify(?string $connection = null, bool $entities = true, int $chunk = 1000): LedgerReport
    {
        return $this->manager->verifyLedger(new LedgerVerifyOptions($connection, $entities, $chunk));
    }

    /**
     * @return list<LedgerRecord>
     */
    public function history(Model $model, ?string $seal = null, int $limit = 50): array
    {
        return $this->manager->ledgerHistory($model, $seal, $limit);
    }

    /**
     * The newest checkpoint of a connection (unverified), or null.
     */
    public function head(?string $connection = null): ?CheckpointRecord
    {
        return $this->manager->ledgerHead($connection);
    }

    /**
     * The configured anchor driver names.
     *
     * @return list<string>
     */
    public function anchors(): array
    {
        return $this->manager->anchors();
    }
}
