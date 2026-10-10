<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Keys;

use Closure;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Keys\KeyReseal;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Re-seal every database key in the current envelope format (`sentinel.key/2`), which binds
 * its label — the upgrade step from 1.1 before `sentinel.keys.require_bound_label` is turned
 * on. Ring by ring (every ring with a database store, or the one named), row by row under its
 * lock; idempotent; a row that fails its integrity check is never re-sealed.
 *
 * Behind `sentinel:key:reseal` only — a one-time migration of Sentinel's own storage, not a
 * domain operation, so it stays off the facade (and the fake has no envelopes to upgrade).
 *
 * @internal
 */
final readonly class ResealKeyEnvelopesAction
{
    public function __construct(private KeyStoreManager $keys) {}

    /**
     * @param  (Closure(KeyReseal): void)|null  $before  sees each key's outcome before it is written
     * @return list<KeyReseal>
     *
     * @throws SealingMisconfiguredException when the named ring is not configured
     * @throws KeyDriverException when the named ring stores no keys in the database
     */
    public function execute(?string $ring = null, bool $dryRun = false, ?Closure $before = null): array
    {
        if ($ring !== null) {
            Settings::ring($ring);
        }

        $rings = $ring === null ? array_values(array_filter(Settings::rings(), $this->keys->hasWritableStore(...))) : [$ring];
        $before ??= static function (): void {};
        $results = [];

        foreach ($rings as $name) {
            $store = $this->keys->writableStore($name);

            foreach (Key::query()->where('ring', $name)->orderBy('id')->pluck('kid') as $keyId) {
                $results[] = $store->reseal((string) $keyId, $dryRun, $before);
            }
        }

        $this->keys->flush();

        return $results;
    }
}
