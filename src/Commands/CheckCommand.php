<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Sentinel\DataTransferObjects\HealthCheck;
use RoundlyConsulting\Sentinel\Enums\HealthStatus;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * The installation health check (`Sentinel::check()`): signing keys, APP_KEY, tables,
 * models, anchors, checkpoint backlog, scheduling, seals on retired keys and stores. Exits 1
 * on a failure — and, with `--strict`, on a warning too. Never prints key material or key ids.
 */
final class CheckCommand extends Command
{
    protected $signature = 'sentinel:check
        {--json : Print the report as JSON}
        {--strict : Warnings fail the run too}';

    protected $description = 'Check the Sentinel installation: keys, tables, models, anchors, schedule';

    public function handle(SentinelManager $sentinel): int
    {
        $report = $sentinel->check();
        $failed = $report->failed() || ($this->option('strict') && $report->warnings() !== []);

        if ($this->option('json')) {
            $this->line((string) json_encode([...$report->toArray(), 'failed' => $failed], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));

            return $failed ? self::FAILURE : self::SUCCESS;
        }

        foreach ($report->checks as $check) {
            $this->components->twoColumnDetail(self::label($check), $check->message);
        }

        $this->newLine();

        match (true) {
            $report->failed() => $this->components->error('Sentinel is not set up correctly.'),
            $report->warnings() !== [] => $this->components->warn('Sentinel works, with warnings.'),
            default => $this->components->info('Sentinel is set up correctly.'),
        };

        return $failed ? self::FAILURE : self::SUCCESS;
    }

    private static function label(HealthCheck $check): string
    {
        return match ($check->status) {
            HealthStatus::Ok => "<fg=green>✔</> {$check->name}",
            HealthStatus::Warning => "<fg=yellow>!</> {$check->name}",
            HealthStatus::Failure => "<fg=red>✘</> {$check->name}",
        };
    }
}
