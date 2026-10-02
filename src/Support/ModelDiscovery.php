<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;

/**
 * The sealable model classes Sentinel knows: `sentinel.models` first, then every class that
 * has seal rows or ledger entries on a `ledger.connections` entry (morph-map aware),
 * alphabetically. A stored type that no longer resolves to a sealable model is reported as
 * unresolved — its seals would otherwise go unverified without a word.
 *
 * @internal
 */
final readonly class ModelDiscovery
{
    /**
     * @param  list<class-string<Model>>  $models  configured first, then discovered
     * @param  int  $configured  how many of `models` come from `sentinel.models`
     * @param  list<string>  $unresolved  stored types that are not a sealable model class
     */
    private function __construct(
        public array $models,
        public int $configured,
        public array $unresolved,
    ) {}

    public static function run(): self
    {
        $configured = Settings::models();
        $types = [];

        foreach (Settings::ledgerConnections() as $connection) {
            foreach ([Tables::sealsOn($connection), Tables::ledgerOn($connection)] as $query) {
                foreach ($query->toBase()->distinct()->pluck('sealable_type') as $type) {
                    if (is_string($type) && $type !== '') {
                        $types[$type] = true;
                    }
                }
            }
        }

        $discovered = [];
        $unresolved = [];

        foreach (array_keys($types) as $type) {
            $class = Relation::getMorphedModel($type) ?? $type;

            if (self::isSealable($class)) {
                $discovered[$class] = true;
            } else {
                $unresolved[] = $type;
            }
        }

        $discovered = array_keys($discovered);
        sort($discovered);
        sort($unresolved);

        return new self(
            array_values(array_unique([...$configured, ...$discovered])),
            count(array_unique($configured)),
            $unresolved,
        );
    }

    /**
     * @phpstan-assert-if-true class-string<Model> $class
     */
    public static function isSealable(string $class): bool
    {
        return class_exists($class)
            && is_subclass_of($class, Model::class)
            && is_subclass_of($class, Sealable::class)
            && in_array(HasSeals::class, class_uses_recursive($class), true);
    }
}
