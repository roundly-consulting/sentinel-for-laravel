<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands\Concerns;

use Illuminate\Console\Command;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealReport;

/**
 * The shared output of the re-sealing commands: counts, then every skipped row (identifiers,
 * statuses and attribute names only). Skipped or failed rows exit 1.
 *
 * @phpstan-require-extends Command
 */
trait ReportsReseals
{
    protected function reportReseal(ResealReport $report, string $resealed = 'Re-sealed'): int
    {
        $prefix = $report->dryRun ? '[dry run] ' : '';

        $this->components->twoColumnDetail($prefix.$resealed, (string) $report->resealed);
        $this->components->twoColumnDetail($prefix.'Acknowledged', (string) $report->acknowledged);
        $this->components->twoColumnDetail($prefix.'Skipped', (string) $report->skipped);
        $this->components->twoColumnDetail($prefix.'Failed', (string) $report->failed);

        foreach ($report->skippedResults as $result) {
            $this->line(sprintf(
                '  %s:%s  seal=%s  %s%s',
                $result->sealableType, $result->sealableId, $result->seal, $result->status->value,
                $result->reason === null ? '' : " ({$result->reason})",
            ));
        }

        if ($report->skippedResults !== []) {
            $this->components->warn('Rows that are not intact were left alone. Acknowledge them deliberately (--acknowledge=<reason>) once the change is understood.');
        }

        return $report->skipped > 0 && $report->skippedResults !== [] || $report->failed > 0 ? self::FAILURE : self::SUCCESS;
    }
}
