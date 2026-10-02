<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReadsOptions;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReportsReseals;
use RoundlyConsulting\Sentinel\Commands\Concerns\ShowsProgress;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealOptions;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * Re-seal a model's rows with the current key — after a rotation, a definition change or a
 * format upgrade. Never launders: rows that are not intact are skipped and listed (exit 1)
 * unless `--acknowledge=<reason>` explicitly acknowledges them.
 */
final class ResealCommand extends Command
{
    use ReadsOptions;
    use ReportsReseals;
    use ShowsProgress;

    protected $signature = 'sentinel:reseal
        {model : A model class or morph alias}
        {--seal= : Only this seal}
        {--from-key= : Only rows sealed by this key id}
        {--only-outdated : Only rows whose seal definition changed}
        {--upgrade-format : Only rows of an older canonical format}
        {--chunk=500 : Rows per chunk}
        {--dry-run : Count, write nothing}
        {--acknowledge= : A reason — acknowledge rows that are not intact instead of skipping them}';

    protected $description = 'Re-seal Sentinel seals with the current key (never launders)';

    public function handle(SentinelManager $sentinel): int
    {
        try {
            $progress = $this->progress();
            $report = $sentinel->reseal(new ResealOptions(
                $this->sealableClass($this->stringArgument('model')),
                $this->stringOption('seal'),
                $this->stringOption('from-key'),
                (bool) $this->option('only-outdated'),
                $this->intOption('chunk', 1, 100000) ?? 500,
                (bool) $this->option('dry-run'),
                $this->stringOption('acknowledge'),
                null,
                (bool) $this->option('upgrade-format'),
                $progress,
            ));
        } catch (SentinelException $exception) {
            $this->components->error($exception->getMessage());

            return self::INVALID;
        } finally {
            $this->finishProgress();
        }

        return $this->reportReseal($report);
    }
}
