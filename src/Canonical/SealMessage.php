<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Canonical;

use Carbon\CarbonImmutable;
use Closure;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * The canonical seal document (`sentinel.seal/1`, plan §4.3.4) whose UTF-8 JCS bytes are
 * MAC'd or signed. FROZEN: any change here is format `/2`, and the frozen vectors fail the
 * build first.
 *
 * Binds the app context, morph class, table, key, tenant scope, seal name, per-entity
 * version and the previous seal's digest — so values (or a whole seal row) copied to
 * another row, model, seal, tenant or app never verify.
 *
 * @internal
 */
final readonly class SealMessage
{
    public const string VERSION = 'sentinel.seal/1';

    /**
     * The attribute document of a seal with computed fields (see {@see attributeBytes()}).
     */
    public const string ATTRIBUTES_VERSION = 'sentinel.seal-attributes/1';

    /**
     * @param  list<FieldValue>  $fields
     */
    public function __construct(
        public string $context,
        public string $type,
        public string $table,
        public string $id,
        public string $scope,
        public string $seal,
        public int $version,
        public ?string $previous,
        public string $ring,
        public string $keyId,
        public Algorithm $algorithm,
        public CarbonImmutable $at,
        public array $fields,
    ) {}

    public function bytes(): string
    {
        return $this->encode(self::VERSION, static fn (FieldValue $field): array => $field->tuple());
    }

    /**
     * The same document with each computed field reduced to its name: everything but the
     * computed values — every attribute, the full field list, the key, the version and the
     * chain — stays bound. Its MAC (`attributes_mac`) proves that a seal whose MAC fails
     * drifted only in computed values; unlike the field tags, it cannot be forged or trimmed.
     */
    public function attributeBytes(): string
    {
        return $this->encode(self::ATTRIBUTES_VERSION, static fn (FieldValue $field): array => str_starts_with($field->name, 'c:') ? [$field->name] : $field->tuple());
    }

    public function hasComputed(): bool
    {
        foreach ($this->fields as $field) {
            if (str_starts_with($field->name, 'c:')) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  Closure(FieldValue): list<string|null>  $tuple
     */
    private function encode(string $version, Closure $tuple): string
    {
        $fields = $this->fields;

        usort($fields, static fn (FieldValue $a, FieldValue $b): int => strcmp($a->name, $b->name));

        return Jcs::encode([
            'alg' => $this->algorithm->value,
            'at' => Clock::iso($this->at),
            'ctx' => $this->context,
            'f' => array_map($tuple, $fields),
            'id' => $this->id,
            'kid' => $this->keyId,
            'prev' => $this->previous,
            'ring' => $this->ring,
            'scope' => $this->scope,
            'seal' => $this->seal,
            'table' => $this->table,
            'type' => $this->type,
            'v' => $version,
            'ver' => (string) $this->version,
        ]);
    }
}
