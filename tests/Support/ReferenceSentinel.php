<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Support;

/**
 * A pure, in-memory model of what Sentinel must report (plan §12.6) for one strict seal over
 * one integer column, written from the semantics contract — not from the engine:
 *
 *  - a seal covers the value the row held when it was sealed, at a per-entity version that
 *    is max(seal row, ledger head) + 1 on every seal event (tombstones included);
 *  - verification: no seal row → missing; row ≠ sealed value → tampered; a ledger head newer
 *    than the seal row → stale; else intact (§4.6);
 *  - Eloquent writes on a non-intact row are refused (D19), deletes never are;
 *  - acknowledging re-seals anything that is not intact; re-sealing only moves intact seals
 *    to the current key (D44);
 *  - the ledger check reports live histories whose seal row is gone or older (§9.7).
 */
final class ReferenceSentinel
{
    /**
     * @var array<int, array{alive: bool, row: int, seal: array{version: int, value: int, key: string}|null, head: int, snapshot: array{row: int, seal: array{version: int, value: int, key: string}|null}|null}>
     */
    private array $entities = [];

    public function __construct(private string $currentKey) {}

    /**
     * @return list<int>
     */
    public function alive(): array
    {
        return array_keys(array_filter($this->entities, static fn (array $entity): bool => $entity['alive']));
    }

    public function hasSnapshot(int $id): bool
    {
        return $this->entities[$id]['snapshot'] !== null;
    }

    public function hasSeal(int $id): bool
    {
        return $this->entities[$id]['seal'] !== null;
    }

    public function row(int $id): int
    {
        return $this->entities[$id]['row'];
    }

    public function created(int $id, int $value): void
    {
        $this->entities[$id] = ['alive' => true, 'row' => $value, 'seal' => null, 'head' => 0, 'snapshot' => null];
        $this->seal($id);
    }

    /**
     * An Eloquent update: false when it must be refused.
     */
    public function update(int $id, int $value): bool
    {
        if ($this->status($id)[0] !== 'intact') {
            return false;
        }

        $this->entities[$id]['row'] = $value;
        $this->seal($id);

        return true;
    }

    public function tamper(int $id, int $value): void
    {
        $this->entities[$id]['row'] = $value;
    }

    public function deleteSeal(int $id): void
    {
        $this->entities[$id]['seal'] = null;
    }

    public function snapshot(int $id): void
    {
        $this->entities[$id]['snapshot'] = ['row' => $this->entities[$id]['row'], 'seal' => $this->entities[$id]['seal']];
    }

    public function restore(int $id): void
    {
        $snapshot = $this->entities[$id]['snapshot'];

        if ($snapshot !== null) {
            $this->entities[$id]['row'] = $snapshot['row'];
            $this->entities[$id]['seal'] = $snapshot['seal'];
        }
    }

    /**
     * Whether an acknowledgement re-seals (an intact model is left alone).
     */
    public function acknowledge(int $id): bool
    {
        if ($this->status($id)[0] === 'intact') {
            return false;
        }

        $this->seal($id);

        return true;
    }

    public function rotated(string $keyId): void
    {
        $this->currentKey = $keyId;
    }

    /**
     * Re-seal every intact row still sealed by an older key; the number re-sealed.
     */
    public function reseal(): int
    {
        $resealed = 0;

        foreach ($this->alive() as $id) {
            if ($this->status($id)[0] === 'intact' && $this->entities[$id]['seal']['key'] !== $this->currentKey) {
                $this->seal($id);
                $resealed++;
            }
        }

        return $resealed;
    }

    public function deleted(int $id): void
    {
        $this->entities[$id]['head'] = $this->nextVersion($id);
        $this->entities[$id]['seal'] = null;
        $this->entities[$id]['alive'] = false;
    }

    /**
     * @return array{0: string, 1: string|null} status and reason
     */
    public function status(int $id): array
    {
        $entity = $this->entities[$id];

        return match (true) {
            $entity['seal'] === null => ['missing', 'seal_deleted'],
            $entity['seal']['value'] !== $entity['row'] => ['tampered', 'mac'],
            $entity['head'] > $entity['seal']['version'] => ['stale', 'newer_version'],
            default => ['intact', null],
        };
    }

    /**
     * @return array{seal: int|null, head: int}
     */
    public function versions(int $id): array
    {
        return ['seal' => $this->entities[$id]['seal']['version'] ?? null, 'head' => $this->entities[$id]['head']];
    }

    /**
     * The entity findings of a ledger check, as sorted "kind:id" strings.
     *
     * @return list<string>
     */
    public function ledgerFindings(): array
    {
        $findings = [];

        foreach ($this->entities as $id => $entity) {
            if (! $entity['alive']) {
                continue;
            }

            if ($entity['seal'] === null) {
                $findings[] = "seal_missing:{$id}";
            } elseif ($entity['seal']['version'] < $entity['head']) {
                $findings[] = "seal_rolled_back:{$id}";
            }
        }

        sort($findings);

        return $findings;
    }

    private function seal(int $id): void
    {
        $version = $this->nextVersion($id);
        $this->entities[$id]['seal'] = ['version' => $version, 'value' => $this->entities[$id]['row'], 'key' => $this->currentKey];
        $this->entities[$id]['head'] = $version;
    }

    private function nextVersion(int $id): int
    {
        return max($this->entities[$id]['seal']['version'] ?? 0, $this->entities[$id]['head']) + 1;
    }
}
