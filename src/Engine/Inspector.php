<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Engine;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Canonical\FieldValue;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Diagnostics for `sentinel:inspect`: the canonical values a seal would cover right now, and
 * the sealed columns a table lacks. Values are personal data — only ever printed on request.
 *
 * @internal
 */
final readonly class Inspector
{
    public function __construct(
        private ReadBack $readBack,
        private DocumentBuilder $documents,
    ) {}

    /**
     * @return list<FieldValue>
     */
    public function values(Model $model, CompiledSeal $seal): array
    {
        $row = $this->readBack->row($model, $seal->readColumns())
            ?? throw SealingFailedException::rowVanished($model->getMorphClass(), $model->getKey());

        return $this->documents->build($model, $seal, $seal->fields, $row, $seal->ring, 'inspect', Algorithm::HmacSha256, 1, null, Clock::now())->fields;
    }

    /**
     * @return list<string>
     */
    public function missingColumns(Model $model, CompiledSeal $seal): array
    {
        $schema = $model->getConnection()->getSchemaBuilder();

        return array_values(array_filter($seal->columns(), static fn (string $column): bool => ! $schema->hasColumn($model->getTable(), $column)));
    }
}
