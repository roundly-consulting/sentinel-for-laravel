<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Ledger;

use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointResult;
use RoundlyConsulting\Sentinel\Events\LedgerCheckpointed;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Ledger\AnchorCodec;
use RoundlyConsulting\Sentinel\Ledger\AnchorManager;
use RoundlyConsulting\Sentinel\Ledger\CheckpointBuilder;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Support\Tables;

/**
 * Fold the next batch of pending ledger entries into a keyed, chained checkpoint and publish
 * it to the configured anchors (after commit, best effort). With nothing pending, anchors
 * that report an older checkpoint (an earlier failure) get the newest one again.
 */
final readonly class CreateCheckpointAction
{
    public function __construct(
        private CheckpointBuilder $builder,
        private AnchorManager $anchors,
        private Dispatcher $events,
    ) {}

    public function execute(CheckpointOptions $options): ?CheckpointResult
    {
        $batchSize = $options->batchSize ?? Settings::ledgerBatchSize();

        if ($batchSize < 1 || $batchSize > 100000) {
            throw InvalidSentinelConfigurationException::invalidValue('ledger.batch_size', 'must be between 1 and 100000');
        }

        // A misconfigured anchor fails before anything is written, not after the commit.
        $this->anchors->anchors();

        $connection = Tables::connectionName($options->connection);
        $checkpoint = $this->builder->build($options->connection, $batchSize);

        if ($checkpoint === null) {
            $tail = Tables::checkpoints($options->connection)->orderByDesc('seq')->first();
            $payload = $tail === null ? null : AnchorCodec::fromCheckpoint($tail, $connection);

            if ($payload !== null) {
                $this->anchors->publish($payload, onlyLagging: true);
            }

            return null;
        }

        $seq = (int) $checkpoint->getRawOriginal('seq');
        $entries = (int) $checkpoint->getRawOriginal('entries');
        $root = (string) $checkpoint->getRawOriginal('root');

        $this->events->dispatch(new LedgerCheckpointed($connection, $seq, $entries, $root));

        $payload = AnchorCodec::fromCheckpoint($checkpoint, $connection);

        return new CheckpointResult($connection, $seq, $entries, $root, $payload === null ? [] : $this->anchors->publish($payload));
    }
}
