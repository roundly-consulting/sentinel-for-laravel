<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReadsOptions;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReportsReseals;
use RoundlyConsulting\Sentinel\DataTransferObjects\BaselineOptions;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * Adopt existing rows: seal every row that was never sealed (event `baseline`, the reason
 * recorded). Rows whose ledger history shows a seal that went missing are listed, never
 * baselined (exit 1).
 */
final class SealMissingCommand extends Command
{
    use ReadsOptions;
    use ReportsReseals;

    protected $signature = 'sentinel:seal-missing
        {model : A model class or morph alias}
        {--seal= : Only this seal}
        {--reason= : Why these rows are trusted (required, recorded in the ledger)}
        {--chunk=500 : Rows per chunk}';

    protected $description = 'Seal rows that were never sealed (baseline)';

    public function handle(SentinelManager $sentinel): int
    {
        $reason = $this->stringOption('reason');

        if ($reason === null) {
            $this->components->error('A --reason is required: it is recorded in the ledger with every baseline seal.');

            return self::INVALID;
        }

        try {
            $report = $sentinel->sealMissing(new BaselineOptions(
                $this->sealableClass($this->stringArgument('model')), $this->stringOption('seal'), $reason, $this->intOption('chunk', 1, 100000) ?? 500,
            ));
        } catch (SentinelException $exception) {
            $this->components->error($exception->getMessage());

            return self::INVALID;
        }

        return $this->reportReseal($report, 'Baselined');
    }
}
