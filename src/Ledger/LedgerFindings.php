<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Ledger;

use Illuminate\Database\Eloquent\Relations\Relation;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * The mutable state of one ledger verification run: findings, counters, and the rings each
 * (model, seal) accepts.
 *
 * @internal
 */
final class LedgerFindings
{
    /** @var list<LedgerFinding> */
    public array $findings = [];

    public int $checkpoints = 0;

    public int $entries = 0;

    public int $anchors = 0;

    /** @var array<string, list<string>> */
    private array $rings = [];

    public function __construct(
        private readonly DefinitionRegistry $registry,
        public string $connection = '',
    ) {}

    public function add(LedgerFindingKind $kind, string $detail, ?int $seq = null, ?LedgerEntry $entry = null, ?string $type = null, int|string|null $id = null, ?string $seal = null): void
    {
        $this->findings[] = new LedgerFinding(
            $kind,
            $seq,
            $entry === null ? null : (int) $entry->getKey(),
            $type ?? ($entry === null ? null : (string) $entry->getRawOriginal('sealable_type')),
            $id ?? self::id($entry),
            $seal ?? ($entry === null ? null : (string) $entry->getRawOriginal('seal')),
            $detail,
            $this->connection,
        );
    }

    /**
     * @return list<LedgerFinding>
     */
    public function violationsOf(string $connection): array
    {
        return array_values(array_filter(
            $this->findings,
            static fn (LedgerFinding $finding): bool => $finding->connection === $connection && $finding->isViolation(),
        ));
    }

    /**
     * The rings an entry's key may come from: the seal's own ring and acceptRings() — or,
     * for a model Sentinel can no longer resolve, the ledger and default rings.
     *
     * @return list<string>
     */
    public function ringsFor(LedgerEntry $entry): array
    {
        $type = (string) $entry->getRawOriginal('sealable_type');
        $seal = (string) $entry->getRawOriginal('seal');

        return $this->rings["{$type}\0{$seal}"] ??= $this->resolveRings($type, $seal);
    }

    /**
     * @return list<string>
     */
    private function resolveRings(string $type, string $seal): array
    {
        $class = Relation::getMorphedModel($type) ?? $type;

        if (class_exists($class) && is_subclass_of($class, Sealable::class)) {
            try {
                $compiled = $this->registry->for($class);

                if (isset($compiled->seals[$seal])) {
                    return [$compiled->seals[$seal]->ring, ...$compiled->seals[$seal]->acceptRings];
                }
            } catch (SentinelException) {
                // A definition that no longer compiles: fall back to the ledger rings.
            }
        }

        return Settings::ledgerRings();
    }

    private static function id(?LedgerEntry $entry): int|string|null
    {
        $id = $entry?->getRawOriginal('sealable_id');

        return is_int($id) || is_string($id) ? $id : null;
    }
}
