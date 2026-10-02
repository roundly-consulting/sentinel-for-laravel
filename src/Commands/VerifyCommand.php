<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Console\Isolatable;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReadsOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerVerifyOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\StatusCount;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\Ledger\AnchorCodec;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Scan sealed models (and, with --ledger, the ledger itself) for cron or CI. Exits 1 when a
 * failing status (`--fail-on`, default: every failure) or a ledger integrity violation is
 * found; a checkpoint backlog or an unreachable anchor fails the run only when named in
 * `--fail-on`. Prints identifiers, statuses and attribute names — never values.
 */
final class VerifyCommand extends Command implements Isolatable
{
    use ReadsOptions;

    protected $signature = 'sentinel:verify
        {model?* : Model classes or morph aliases (none: sentinel.models)}
        {--seal= : Only this seal}
        {--chunk=500 : Rows per chunk}
        {--limit= : At most this many rows in total}
        {--ledger : Also verify checkpoints, anchors and every entity\'s ledger head}
        {--anchor= : The JSON payload of a write-only (log) anchor to compare}
        {--check-schema : Check that every sealed column exists before scanning}
        {--json : Print the report as JSON}
        {--fail-on=* : Statuses or ledger findings that fail the run (default: every failure and violation)}
        {--max-findings=1000 : List at most this many findings}';

    protected $description = 'Verify sealed models and the Sentinel ledger';

    public function handle(SentinelManager $sentinel): int
    {
        try {
            [$statuses, $kinds] = $this->failOn();
            $models = array_map($this->sealableClass(...), $this->models());
            $chunk = $this->intOption('chunk', 1, 100000) ?? 500;
            $anchor = $this->stringOption('anchor');

            $scan = $sentinel->scan(new ScanOptions(
                $models, $this->stringOption('seal'), $chunk, true, $this->intOption('limit'),
                $this->intOption('max-findings', 0, 1000000) ?? 1000, (bool) $this->option('check-schema'),
            ));

            $ledger = $this->option('ledger') ? $sentinel->verifyLedger(new LedgerVerifyOptions(
                null, true, max($chunk, 100), $anchor === null ? null : AnchorCodec::decode($anchor),
            )) : null;
        } catch (SentinelException $exception) {
            $this->components->error($exception->getMessage());

            return self::INVALID;
        }

        if ($models === [] && ! $this->option('json')) {
            $this->components->warn('No models to scan: pass model classes or list them in sentinel.models.');
        }

        $this->option('json') ? $this->json($scan, $ledger) : $this->human($scan, $ledger);

        $failed = $scan->hasFindings(...$statuses) || ($ledger !== null && array_filter(
            $ledger->findings,
            static fn (LedgerFinding $finding): bool => $finding->isViolation() || in_array($finding->kind, $kinds, true),
        ) !== []);

        return $failed ? self::FAILURE : self::SUCCESS;
    }

    /**
     * @return list<string>
     */
    private function models(): array
    {
        $given = $this->listInput('model', argument: true);

        return $given !== [] ? $given : Settings::models();
    }

    /**
     * @return array{0: list<VerificationStatus>, 1: list<LedgerFindingKind>}
     */
    private function failOn(): array
    {
        $statuses = [];
        $kinds = [];
        foreach ($this->listInput('fail-on') as $value) {
            foreach (explode(',', $value) as $name) {
                $name = trim($name);
                $status = VerificationStatus::tryFrom($name);
                $kind = LedgerFindingKind::tryFrom($name);

                match (true) {
                    $status !== null => $statuses[] = $status,
                    $kind !== null => $kinds[] = $kind,
                    $name === '' => null,
                    default => throw InvalidSentinelConfigurationException::invalidOption('fail-on', "names an unknown status or ledger finding [{$name}]"),
                };
            }
        }

        return [$statuses, $kinds];
    }

    private function human(ScanReport $scan, ?LedgerReport $ledger): void
    {
        $this->components->twoColumnDetail('Seals verified', (string) $scan->scanned);
        $this->table(['Status', 'Count'], array_map(
            static fn (StatusCount $count): array => [self::label($count->status), (string) $count->count],
            $scan->counts,
        ));

        foreach ($scan->findings as $finding) {
            $this->line(sprintf(
                '  %s:%s  seal=%s  %s%s%s',
                $finding->sealableType, $finding->sealableId, $finding->seal, $finding->status->value,
                $finding->reason === null ? '' : " ({$finding->reason})",
                $finding->changedAttributes === null ? '' : '  changed='.implode(',', $finding->changedAttributes),
            ));
        }

        if ($scan->truncated) {
            $this->components->warn('More findings exist than --max-findings lists.');
        }

        if ($ledger === null) {
            return;
        }

        $this->newLine();
        $this->components->twoColumnDetail('Checkpoints verified', (string) $ledger->checkpoints);
        $this->components->twoColumnDetail('Ledger entries verified', (string) $ledger->entries);
        $this->components->twoColumnDetail('Anchors compared', (string) $ledger->anchorsChecked);

        if (Settings::anchors() === []) {
            $this->components->warn('No anchor is configured: a rollback of the whole database is undetectable.');
        }

        foreach ($ledger->findings as $finding) {
            $this->line(sprintf(
                '  [%s] %s%s%s — %s',
                $finding->connection, $finding->kind->value,
                $finding->seq === null ? '' : " seq={$finding->seq}",
                $finding->sealableType === null ? '' : " {$finding->sealableType}:{$finding->sealableId} seal={$finding->seal}",
                $finding->detail,
            ));
        }

        $ledger->clean() ? $this->components->info('The ledger is intact.') : $this->components->error('The ledger has integrity violations.');
    }

    private function json(ScanReport $scan, ?LedgerReport $ledger): void
    {
        $this->line((string) json_encode([
            'scanned' => $scan->scanned,
            'counts' => array_map(static fn (StatusCount $count): array => ['status' => $count->status->value, 'count' => $count->count], $scan->counts),
            'findings' => array_map(static fn (VerificationResult $result): array => $result->toArray(), $scan->findings),
            'truncated' => $scan->truncated,
            'ledger' => $ledger === null ? null : [
                'checkpoints' => $ledger->checkpoints,
                'entries' => $ledger->entries,
                'anchors_checked' => $ledger->anchorsChecked,
                'clean' => $ledger->clean(),
                'findings' => array_map(static fn (LedgerFinding $finding): array => $finding->toArray(), $ledger->findings),
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    private static function label(VerificationStatus $status): string
    {
        $label = trans('sentinel::statuses.'.$status->value);

        return is_string($label) ? $label : $status->value;
    }
}
