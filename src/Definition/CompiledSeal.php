<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Definition;

use Closure;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\TamperedWritePolicy;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * A validated, immutable seal of one model class. Compiled once per process from the model's
 * code, so it is safe to keep across Octane requests.
 */
final readonly class CompiledSeal
{
    /**
     * @param  class-string  $model
     * @param  list<ManifestField>  $fields  sorted by name (bytewise)
     * @param  list<string>  $acceptRings
     * @param  list<Algorithm>  $algorithms
     */
    public function __construct(
        public string $model,
        public string $name,
        public array $fields,
        public string $ring,
        public array $acceptRings,
        public array $algorithms,
        public bool $strict,
        public bool $auto,
        public bool $verifiesOnRetrieve,
        public ?Reaction $retrieveReaction,
        public ?bool $fieldTags,
        public ?Closure $scope,
        public ?TamperedWritePolicy $onTamperedWrite,
    ) {}

    /**
     * The attribute columns, in manifest order.
     *
     * @return list<string>
     */
    public function columns(): array
    {
        $columns = [];

        foreach ($this->fields as $field) {
            if ($field->column !== null) {
                $columns[] = $field->column;
            }
        }

        return $columns;
    }

    public function hasComputed(): bool
    {
        foreach ($this->fields as $field) {
            if ($field->isComputed()) {
                return true;
            }
        }

        return false;
    }

    /**
     * A scope or computed field reads the model itself, so it must see the row as stored.
     */
    public function needsSubject(): bool
    {
        return $this->scope !== null || $this->hasComputed();
    }

    /**
     * What the read-back selects: every column when closures will read the model.
     *
     * @return list<string>
     */
    public function readColumns(): array
    {
        return $this->needsSubject() ? ['*'] : $this->columns();
    }

    public function field(string $name): ?ManifestField
    {
        foreach ($this->fields as $field) {
            if ($field->name === $name) {
                return $field;
            }
        }

        return null;
    }

    /**
     * The manifest as stored on the seal row: `[[name, declaredTag], …]`.
     *
     * @return list<list<string>>
     */
    public function manifest(): array
    {
        return array_map(static fn (ManifestField $field): array => [$field->name, $field->tag()], $this->fields);
    }

    public function acceptsRing(string $ring): bool
    {
        return $ring === $this->ring || in_array($ring, $this->acceptRings, true);
    }

    public function allows(Algorithm $algorithm): bool
    {
        return in_array($algorithm, $this->algorithms, true);
    }

    public function policy(): TamperedWritePolicy
    {
        return $this->onTamperedWrite ?? Settings::onTamperedWrite();
    }

    public function usesFieldTags(): bool
    {
        return $this->fieldTags ?? Settings::fieldTags();
    }
}
