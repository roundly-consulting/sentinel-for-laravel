<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

/**
 * How many seals one key made, summed over every connection that holds seals
 * (`sentinel.ledger.connections`). The one counting path of `sentinel:key:list`,
 * `sentinel:key:retire` and the health check's `retired_keys`, so they never disagree in a
 * multi-connection app.
 *
 * @internal
 */
final readonly class SealUsage
{
    private function __construct(
        public string $ring,
        public string $keyId,
        public int $seals,
    ) {}

    /**
     * Every (ring, key id) that seal rows name, with its count — optionally only one ring
     * and/or one key id. Stored values are read as they are (a damaged row counts under the
     * ring and key id it claims).
     *
     * @return list<self>
     */
    public static function perKey(?string $ring = null, ?string $keyId = null): array
    {
        $totals = [];

        foreach (Settings::ledgerConnections() as $connection) {
            $query = Tables::sealsOn($connection)->toBase()->select(['ring', 'key_id'])->selectRaw('count(*) as seals')->groupBy('ring', 'key_id');

            if ($ring !== null) {
                $query->where('ring', $ring);
            }

            if ($keyId !== null) {
                $query->where('key_id', $keyId);
            }

            foreach ($query->get() as $row) {
                $usage = new self(self::text($row->ring ?? null), self::text($row->key_id ?? null), is_numeric($row->seals ?? null) ? (int) $row->seals : 0);
                $id = $usage->ring."\0".$usage->keyId;
                $totals[$id] = new self($usage->ring, $usage->keyId, ($totals[$id]->seals ?? 0) + $usage->seals);
            }
        }

        return array_values($totals);
    }

    /**
     * The seals one key made, on every connection.
     */
    public static function of(string $ring, string $keyId): int
    {
        return array_sum(array_map(static fn (self $usage): int => $usage->seals, self::perKey($ring, $keyId)));
    }

    private static function text(mixed $value): string
    {
        return is_string($value) || is_int($value) ? (string) $value : '';
    }
}
