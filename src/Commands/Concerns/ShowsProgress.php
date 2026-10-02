<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands\Concerns;

use Closure;
use Illuminate\Console\Command;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Output\ConsoleOutputInterface;

/**
 * An indeterminate progress bar (rows processed — no count query) on the error output, so a
 * long scan shows it is alive without polluting stdout. Only on a decorated terminal and
 * never with --json.
 *
 * @phpstan-require-extends Command
 */
trait ShowsProgress
{
    private ?ProgressBar $progressBar = null;

    /**
     * The progress callback to hand to a scan, or null when no bar is shown.
     *
     * @return (Closure(int): void)|null
     */
    protected function progress(bool $json = false): ?Closure
    {
        $this->progressBar = null;
        $output = $this->output->getOutput();
        $target = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;

        if ($json || ! $target->isDecorated()) {
            return null;
        }

        $bar = new ProgressBar($target);
        $bar->setFormat(' %current% rows %elapsed:6s%');
        $bar->start();
        $this->progressBar = $bar;

        return static function (int $processed) use ($bar): void {
            $bar->setProgress($processed);
        };
    }

    protected function finishProgress(): void
    {
        if ($this->progressBar !== null) {
            $this->progressBar->finish();
            $this->progressBar->clear();
            $this->progressBar = null;
        }
    }
}
