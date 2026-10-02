<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReadsOptions;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\Keys\EnvSnippet;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * Retire a database key (its verification period ends now).
 */
final class KeyRetireCommand extends Command
{
    use ReadsOptions;

    protected $signature = 'sentinel:key:retire
        {kid : The key id}
        {--ring= : The key ring (default: sentinel.keys.default_ring)}
        {--force : Retire even if seals still use the key}';

    protected $description = 'Retire a Sentinel key';

    public function handle(SentinelManager $sentinel): int
    {
        $ring = $this->ringOption();
        $keyId = (string) $this->argument('kid');

        try {
            $key = $sentinel->findKey($ring, $keyId);

            if ($key === null) {
                $this->components->error("Key ring [{$ring}] has no key [{$keyId}].");

                return self::FAILURE;
            }

            if ($key->driver !== 'database') {
                $this->components->warn('This key comes from configuration: remove it from '.EnvSnippet::previousVariable($ring).' (or the current key variables) to retire it.');

                return self::SUCCESS;
            }

            $sentinel->retireKey($ring, $keyId);
        } catch (SentinelException $exception) {
            $this->components->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->components->info("Retired key [{$ring}:{$keyId}].");

        return self::SUCCESS;
    }
}
