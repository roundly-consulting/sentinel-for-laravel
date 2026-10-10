<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReadsOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\GenerateKeyRequest;
use RoundlyConsulting\Sentinel\Enums\KeyDestination;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Generate a key. Without `--database` it prints environment lines to stdout (never writes
 * `.env`); with it, it stores the encrypted envelope and prints only the kid and public key.
 */
final class KeyGenerateCommand extends Command
{
    use ReadsOptions;

    protected $signature = 'sentinel:key:generate
        {--ring= : The key ring (default: sentinel.keys.default_ring)}
        {--algorithm=hmac-sha256 : hmac-sha256, hmac-sha384, hmac-sha512, ed25519, ecdsa-p256-sha256 or ecdsa-p384-sha384}
        {--kid= : The key id (default: <ring>-<Ymd>-<random>)}
        {--database : Store the key, encrypted, in sentinel_keys instead of printing environment lines}
        {--activate-at= : When a database key starts signing (UTC unless an offset is given)}
        {--owner-type= : Morph type or class of the model that owns the key}
        {--owner-id= : Key of the model that owns the key}
        {--label= : A short label, bound into the key (UTF-8, at most 191 characters)}';

    protected $description = 'Generate a Sentinel seal or HTTP-signature key';

    public function handle(SentinelManager $sentinel): int
    {
        $algorithm = $this->algorithmOption();

        if ($algorithm === null) {
            $this->components->error('Unknown --algorithm. Use hmac-sha256, hmac-sha384, hmac-sha512, ed25519, ecdsa-p256-sha256 or ecdsa-p384-sha384.');

            return self::FAILURE;
        }

        $ring = $this->ringOption();
        $database = (bool) $this->option('database');

        if (($this->stringOption('owner-type') !== null || $this->stringOption('owner-id') !== null) && $this->ownerOption() === null) {
            $this->components->error('The --owner-type/--owner-id model was not found.');

            return self::FAILURE;
        }

        try {
            $key = $sentinel->generateKey(new GenerateKeyRequest(
                $ring, $algorithm, $this->stringOption('kid'), $database ? KeyDestination::Database : KeyDestination::Config,
                $this->dateOption('activate-at'), $this->ownerOption(), $this->stringOption('label'),
            ));
        } catch (SentinelException $exception) {
            $this->components->error($exception->getMessage());

            return self::FAILURE;
        }

        if ($key->envSnippet !== null) {
            $this->components->warn('Treat these lines as secrets: add them to the environment — never commit or log them.');

            if (! in_array(Settings::ring($ring)->driver, ['config', 'chain'], true)) {
                $this->components->warn("Ring [{$ring}] does not read config keys (driver: ".Settings::ring($ring)->driver.'); use --database or change its driver.');
            }

            foreach (explode("\n", $key->envSnippet) as $line) {
                $this->line($line);
            }

            return self::SUCCESS;
        }

        $this->components->info("Stored key [{$ring}:{$key->info->keyId}] ({$algorithm->value}).");

        if ($key->publicKey !== null) {
            $this->line("Public key: {$key->publicKey}");
        }

        return self::SUCCESS;
    }
}
