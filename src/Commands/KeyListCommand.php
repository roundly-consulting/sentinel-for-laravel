<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Carbon\CarbonImmutable;
use Illuminate\Console\Command;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReadsOptions;
use RoundlyConsulting\Sentinel\Commands\Concerns\ShowsKeyLabels;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\SealUsage;

/**
 * The key inventory (OWASP ASVS 11.1.1): ring, kid, algorithm, effective status, driver,
 * the seals it made (on every ledger connection), usage periods and label (quoted, escaped).
 * Never prints material.
 */
final class KeyListCommand extends Command
{
    use ReadsOptions;
    use ShowsKeyLabels;

    protected $signature = 'sentinel:key:list {--ring= : Only this ring}';

    protected $description = 'List Sentinel keys (never their material)';

    public function handle(SentinelManager $sentinel): int
    {
        $usage = [];

        try {
            $keys = $sentinel->listKeys($this->stringOption('ring'));

            // Seals per key on every connection that holds seals — the count
            // sentinel:key:retire refuses on.
            foreach (SealUsage::perKey($this->stringOption('ring')) as $counted) {
                $usage[$counted->ring."\0".$counted->keyId] = $counted->seals;
            }
        } catch (SentinelException $exception) {
            $this->components->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->table(
            ['Ring', 'Key id', 'Algorithm', 'Status', 'Driver', 'Can sign', 'Seals', 'Activates', 'Signs until', 'Verifies until', 'Revoked', 'Label'],
            array_map(static fn (KeyInfo $key): array => [
                $key->ring, $key->keyId, $key->algorithm->value, $key->status->value, $key->driver, $key->canSign ? 'yes' : 'no',
                (string) ($usage[$key->ring."\0".$key->keyId] ?? 0),
                self::date($key->activatesAt), self::date($key->signsUntil), self::date($key->verifiesUntil), self::date($key->revokedAt),
                self::shownLabel($key->label, '—'),
            ], $keys),
        );

        $seen = [];

        foreach ($keys as $key) {
            $id = "{$key->ring}:{$key->keyId}";

            if (isset($seen[$id])) {
                $this->components->warn("Key [{$id}] exists in more than one driver; the first in the chain wins.");
            }

            $seen[$id] = true;
        }

        return self::SUCCESS;
    }

    private static function date(?CarbonImmutable $at): string
    {
        return $at === null ? '—' : Clock::iso($at);
    }
}
