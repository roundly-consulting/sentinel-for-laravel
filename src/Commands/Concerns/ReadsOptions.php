<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
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
        $value = is_int($value) ? (string) $value : $value;

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    protected function stringArgument(string $name): string
    {
        $value = $this->argument($name);

        return is_string($value) ? $value : '';
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

    /**
     * A sealable model class from a class name or morph alias.
     *
     * @return class-string<Model>
     *
     * @throws SealingMisconfiguredException
     */
    protected function sealableClass(string $model): string
    {
        $class = Relation::getMorphedModel($model) ?? $model;

        if (! class_exists($class) || ! is_subclass_of($class, Model::class) || ! is_subclass_of($class, Sealable::class)) {
            throw SealingMisconfiguredException::unknownModel($model);
        }

        return $class;
    }

    /**
     * A positive integer option (null when absent).
     */
    protected function intOption(string $name, int $minimum = 1, int $maximum = PHP_INT_MAX): ?int
    {
        $value = $this->stringOption($name);

        if ($value === null) {
            return null;
        }

        if (preg_match('/^\d{1,18}$/D', $value) !== 1 || (int) $value < $minimum || (int) $value > $maximum) {
            throw InvalidSentinelConfigurationException::invalidOption($name, "must be an integer between {$minimum} and {$maximum}");
        }

        return (int) $value;
    }

    /**
     * The non-empty string values of an array option or argument (read untyped, so the result
     * does not depend on how a static analyser infers the signature).
     *
     * @return list<string>
     */
    protected function listInput(string $name, bool $argument = false): array
    {
        $raw = $argument ? $this->input->getArgument($name) : $this->input->getOption($name);
        $values = [];

        foreach (is_array($raw) ? $raw : [$raw] as $value) {
            if (is_string($value) && $value !== '') {
                $values[] = $value;
            }
        }

        return $values;
    }
}
