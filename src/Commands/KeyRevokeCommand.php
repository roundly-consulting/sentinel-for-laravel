<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReadsOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\RevokeKeyRequest;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Revoke a key. Database keys are revoked in place (envelope re-encrypted); config keys are
 * revoked through `SENTINEL_REVOKED_KEYS`, whose new value this prints.
 */
final class KeyRevokeCommand extends Command
{
    use ReadsOptions;

    protected $signature = 'sentinel:key:revoke
        {kid : The key id}
        {--ring= : The key ring (default: sentinel.keys.default_ring)}
        {--reason= : Why the key is revoked (required)}';

    protected $description = 'Revoke a Sentinel key';

    public function handle(SentinelManager $sentinel): int
    {
        $ring = $this->ringOption();
        $keyId = $this->stringArgument('kid');
        $reason = $this->stringOption('reason');

        if ($reason === null) {
            $this->components->error('A --reason is required.');

            return self::FAILURE;
        }

        try {
            $key = $sentinel->findKey($ring, $keyId);

            if ($key === null) {
                $this->components->error("Key ring [{$ring}] has no key [{$keyId}].");

                return self::FAILURE;
            }

            if ($key->driver !== 'database') {
                $entries = [...Settings::revokedKeys(), "{$ring}:{$keyId}"];
                $this->components->warn('This key comes from configuration. Revoke it by setting:');
                $this->line('SENTINEL_REVOKED_KEYS="'.implode(',', array_values(array_unique($entries))).'"');

                return self::SUCCESS;
            }

            $sentinel->revokeKey(new RevokeKeyRequest($ring, $keyId, $reason));
        } catch (SentinelException $exception) {
            $this->components->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->components->info("Revoked key [{$ring}:{$keyId}].");

        return self::SUCCESS;
    }
}
