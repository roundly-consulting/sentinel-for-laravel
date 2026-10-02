<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Support\Settings;
use Throwable;

/**
 * Typed reads of console options.
 *
 * @phpstan-require-extends Command
 */
trait ReadsOptions
{
    protected function stringOption(string $name): ?string
    {
        $value = $this->option($name);

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    protected function ringOption(): string
    {
        return $this->stringOption('ring') ?? Settings::defaultRing();
    }

    protected function algorithmOption(string $name = 'algorithm'): ?Algorithm
    {
        $value = $this->stringOption($name);

        return $value === null ? null : Algorithm::tryFrom($value);
    }

    /**
     * A point in time: UTC unless the value carries an offset.
     */
    protected function dateOption(string $name): ?CarbonImmutable
    {
        $value = $this->stringOption($name);

        return $value === null ? null : CarbonImmutable::parse($value, 'UTC')->utc();
    }

    protected function ownerOption(): ?Model
    {
        $type = $this->stringOption('owner-type');
        $id = $this->stringOption('owner-id');

        if ($type === null || $id === null) {
            return null;
        }

        $class = Relation::getMorphedModel($type) ?? $type;

        try {
            $owner = is_a($class, Model::class, true) ? $class::query()->find($id) : null;
        } catch (Throwable) {
            $owner = null;
        }

        return $owner instanceof Model ? $owner : null;
    }
}
