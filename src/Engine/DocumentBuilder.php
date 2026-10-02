<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Engine;

use BackedEnum;
use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Canonical\Normalizer;
use RoundlyConsulting\Sentinel\Canonical\SealMessage;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\ManifestField;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\CanonicalizationException;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;
use Stringable;
use Throwable;

/**
 * Builds the canonical seal document of a model (plan §9.2) from raw row values and computed
 * fields, binding context, morph class, table, key, scope, seal name, version and chain.
 *
 * @internal
 */
final readonly class DocumentBuilder
{
    public function __construct(
        private Normalizer $normalizer,
        private SealingScope $scope,
    ) {}

    /**
     * @param  list<ManifestField>  $fields
     * @param  array<string, mixed>  $row  raw values of every attribute field
     *
     * @throws CanonicalizationException
     */
    public function build(
        Model $model,
        CompiledSeal $seal,
        array $fields,
        array $row,
        string $ring,
        string $keyId,
        Algorithm $algorithm,
        int $version,
        ?string $previous,
        CarbonImmutable $at,
    ): SealMessage {
        $values = [];
        $subject = $seal->needsSubject() ? $this->subject($model, $row) : $model;

        foreach ($fields as $field) {
            $resolver = $field->resolver;

            // Related sealed models a resolver loads are covered by this seal: their own
            // verify-on-retrieve must not fire (or recurse) from inside sealing/verification.
            $raw = $resolver !== null
                ? $this->scope->withoutVerification(static fn (): mixed => $resolver($subject))
                : $this->attribute($model, $field, $row);

            $values[] = $this->normalizer->normalize($field->name, $field->type, $raw);
        }

        return new SealMessage(
            Settings::context(), $model->getMorphClass(), $model->getTable(), (string) $model->getKey(),
            $this->scope->withoutVerification(fn (): string => $this->scope($seal, $subject)),
            $seal->name, $version, $previous, $ring, $keyId, $algorithm, $at, $values,
        );
    }

    /**
     * The tenant (or other) scope bound into the MAC; `""` when the seal declares none.
     */
    public function scope(CompiledSeal $seal, Model $model): string
    {
        if ($seal->scope === null) {
            return '';
        }

        $scope = ($seal->scope)($model);

        return match (true) {
            $scope === null => '',
            is_string($scope), is_int($scope) => (string) $scope,
            $scope instanceof BackedEnum => (string) $scope->value,
            $scope instanceof Stringable => (string) $scope,
            default => throw CanonicalizationException::unsupportedType(get_debug_type($scope), 'scope'),
        };
    }

    /**
     * The model as the database holds it: a fresh instance hydrated from the read-back row
     * (no `retrieved` event, the caller's instance untouched).
     *
     * @param  array<string, mixed>  $row
     */
    private function subject(Model $model, array $row): Model
    {
        $subject = $model->newInstance([], true);
        $subject->setRawAttributes($row, true);

        return $subject;
    }

    /**
     * @param  array<string, mixed>  $row
     */
    private function attribute(Model $model, ManifestField $field, array $row): mixed
    {
        $raw = $row[(string) $field->column] ?? null;

        if (! $field->isPlaintext() || $raw === null) {
            return $raw;
        }

        // Decrypt through the model's own cast, on a scratch instance (never the caller's).
        $scratch = $model->newInstance([], true);
        $scratch->setRawAttributes([(string) $field->column => $raw], true);

        try {
            return $scratch->getAttribute((string) $field->column);
        } catch (Throwable) {
            throw CanonicalizationException::undecryptable($field->name);
        }
    }
}
