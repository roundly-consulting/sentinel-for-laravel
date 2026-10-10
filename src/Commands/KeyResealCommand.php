<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Sentinel\Actions\Keys\ResealKeyEnvelopesAction;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReadsOptions;
use RoundlyConsulting\Sentinel\Commands\Concerns\ShowsKeyLabels;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\Keys\KeyReseal;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Re-seal database keys in the current envelope format (`sentinel.key/2`), which binds each
 * key's label — the upgrade step from 1.1. Prints `ring:kid → label` for every key before it
 * is bound, so the labels can be checked (`--dry-run` writes nothing); then turn on
 * `sentinel.keys.require_bound_label`. Idempotent. Never re-seals a row that fails its
 * integrity check, or one whose label cannot be bound (exit 1).
 */
final class KeyResealCommand extends Command
{
    use ReadsOptions;
    use ShowsKeyLabels;

    protected $signature = 'sentinel:key:reseal
        {--ring= : Only this ring (default: every ring that stores keys in the database)}
        {--dry-run : Print what would be re-sealed, write nothing}';

    protected $description = 'Re-seal Sentinel database keys so their labels are bound';

    public function handle(ResealKeyEnvelopesAction $reseal): int
    {
        $dryRun = (bool) $this->option('dry-run');

        try {
            $results = $reseal->execute($this->stringOption('ring'), $dryRun, function (KeyReseal $result) use ($dryRun): void {
                $this->show($result, $dryRun);
            });
        } catch (SentinelException $exception) {
            $this->components->error($exception->getMessage());

            return self::FAILURE;
        }

        $count = static fn (string $outcome): int => count(array_filter($results, static fn (KeyReseal $result): bool => $result->outcome === $outcome));
        [$resealed, $current] = [$count(KeyReseal::RESEALED), $count(KeyReseal::CURRENT)];
        [$failed, $refused, $unbindable] = [$count(KeyReseal::FAILED), $count(KeyReseal::REFUSED), $count(KeyReseal::UNBINDABLE)];

        $this->newLine();
        $this->components->info($dryRun
            ? "Dry run: {$resealed} key(s) would be re-sealed, {$current} already bound. Nothing was written."
            : "Re-sealed {$resealed} key(s), {$current} already bound.");

        if ($failed > 0) {
            $this->components->error("{$failed} key(s) fail their integrity check and were not re-sealed — find out why before setting SENTINEL_REQUIRE_BOUND_LABEL=true.");
        }

        if ($refused > 0) {
            $this->components->error("{$refused} legacy key(s) were refused: sentinel.keys.require_bound_label is on. Turn it off, run sentinel:key:reseal again, then turn it back on.");
        }

        if ($unbindable > 0) {
            $this->components->error("{$unbindable} legacy key(s) have a label that is not valid UTF-8, which cannot be bound. Correct the label, then run sentinel:key:reseal again.");
        }

        if ($failed + $refused + $unbindable > 0) {
            return self::FAILURE;
        }

        if (! $dryRun && ! Settings::requireBoundLabel()) {
            $this->line('Check the labels above, then set SENTINEL_REQUIRE_BOUND_LABEL=true.');
        }

        return self::SUCCESS;
    }

    /**
     * One key's line, printed before the key is written: the label it binds, or why it is refused.
     */
    private function show(KeyReseal $result, bool $dryRun): void
    {
        $key = $result->ring.':'.self::shownKeyId($result->keyId);
        $bound = "{$key} → ".self::shownLabel($result->label, '(no label)');

        [$subject, $outcome] = match ($result->outcome) {
            KeyReseal::RESEALED => [$bound, $dryRun ? 'would bind' : '<fg=green>binding</>'],
            KeyReseal::CURRENT => [$bound, 'already bound'],
            KeyReseal::FAILED => [$key, '<fg=red>fails its integrity check — not re-sealed</>'],
            KeyReseal::UNBINDABLE => [$bound, '<fg=red>label is not valid UTF-8 — not re-sealed</>'],
            default => [$key, '<fg=red>legacy envelope refused (require_bound_label is on) — not re-sealed</>'],
        };

        $this->components->twoColumnDetail($subject, $outcome);
    }
}
