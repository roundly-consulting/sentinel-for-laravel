<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Carbon\CarbonImmutable;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Canonical\FieldValue;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReadsOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerRecord;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\ManifestField;
use RoundlyConsulting\Sentinel\Engine\Inspector;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Everything Sentinel knows about one row: per seal, the stored seal, the verification
 * verdict (with the changed attribute names), the manifest and the latest ledger history.
 * Values stay redacted unless `--show-values` — they may be personal data.
 */
final class InspectCommand extends Command
{
    use ReadsOptions;

    protected $signature = 'sentinel:inspect
        {model : A model class or morph alias}
        {id : The row\'s key}
        {--seal= : Only this seal}
        {--show-values : Print the canonical values (DANGEROUS: may print personal data)}
        {--check-schema : Check that every sealed column exists}';

    protected $description = 'Inspect the seals of one row';

    public function handle(SentinelManager $sentinel, Inspector $inspector): int
    {
        try {
            $class = $this->sealableClass($this->stringArgument('model'));
            $id = $this->stringArgument('id');
            $model = $sentinel->withoutVerification(static fn (): ?Model => $class::query()->withoutGlobalScopes()->find($id));

            if (! $model instanceof Model) {
                $this->components->error("[{$class}] has no row [{$id}].");

                return self::FAILURE;
            }

            $definitions = $sentinel->model($class);
            $seal = $this->stringOption('seal');
            $intact = true;

            foreach ($seal === null ? $definitions->seals() : [$seal] as $name) {
                $intact = $this->inspect($sentinel, $inspector, $model, $definitions->definition($name)) && $intact;
            }
        } catch (SentinelException $exception) {
            $this->components->error($exception->getMessage());

            return self::INVALID;
        }

        return $intact ? self::SUCCESS : self::FAILURE;
    }

    private function inspect(SentinelManager $sentinel, Inspector $inspector, Model $model, CompiledSeal $seal): bool
    {
        $this->newLine();
        $this->components->info("Seal [{$seal->name}] of [{$model->getMorphClass()}:{$model->getKey()}]");

        if ($this->option('check-schema')) {
            $missing = $inspector->missingColumns($model, $seal);
            $this->components->twoColumnDetail('Schema', $missing === [] ? 'every sealed column exists' : 'MISSING: '.implode(', ', $missing));
        }

        $record = $sentinel->currentSeal($model, $seal->name);
        $result = $sentinel->verifyIn(VerificationContext::Command, $model, $seal->name);

        $this->components->twoColumnDetail('Status', $result->status->value.($result->reason === null ? '' : " ({$result->reason})"));
        $this->components->twoColumnDetail('Changed attributes', $result->changedAttributes === null ? 'unknown' : ($result->changedAttributes === [] ? 'none' : implode(', ', $result->changedAttributes)));
        $this->components->twoColumnDetail('Stored seal', $record === null ? 'none' : "v{$record->version} · {$record->ring}:{$record->keyId} · {$record->algorithm} · ".self::date($record->sealedAt));
        $this->components->twoColumnDetail('Ring / algorithms', $seal->ring.' · '.implode(', ', array_map(static fn ($algorithm): string => $algorithm->value, $seal->algorithms)));
        $this->components->twoColumnDetail('Manifest', implode(', ', array_map(static fn (ManifestField $field): string => $field->name.':'.$field->tag(), $seal->fields)));

        if ($this->option('show-values')) {
            $this->components->warn('Printing canonical values — they may contain personal data.');

            foreach ($inspector->values($model, $seal) as $value) {
                $this->components->twoColumnDetail(self::field($value), $value->value ?? 'null');
            }
        } else {
            $this->components->twoColumnDetail('Values', 'redacted (--show-values prints them)');
        }

        foreach ($sentinel->ledgerHistory($model, $seal->name, 10) as $entry) {
            $this->line(self::history($entry));
        }

        return $result->isIntact();
    }

    private static function field(FieldValue $value): string
    {
        return "{$value->name} ({$value->tag})";
    }

    private static function history(LedgerRecord $entry): string
    {
        return sprintf(
            '  v%d  %s  %s  %s:%s%s%s',
            $entry->version, $entry->event->value ?? 'unknown', self::date($entry->occurredAt), $entry->ring, $entry->keyId,
            $entry->previousStatus === null ? '' : "  was {$entry->previousStatus->value}",
            $entry->reason === null ? '' : '  reason: '.$entry->reason,
        );
    }

    private static function date(?CarbonImmutable $at): string
    {
        return $at === null ? '—' : Clock::iso($at);
    }
}
