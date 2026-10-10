<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReadsOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ImportKeyRequest;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * Import a key into a ring's database store — a partner's public key or shared secret
 * (verify-only), or your own key pair with `--signing`. The material comes from `--file`
 * (PEM or `base64:…`) or a hidden prompt, never from an argument or option value (shell
 * history); without a terminal and without `--file` the command refuses (exit 2). Prints the
 * key's public description only — never material.
 */
final class KeyImportCommand extends Command
{
    use ReadsOptions;

    private const int MAX_FILE_BYTES = 65536;

    protected $signature = 'sentinel:key:import
        {kid : The key id to store the key under}
        {--ring= : The key ring (default: sentinel.keys.default_ring)}
        {--algorithm= : hmac-sha256, hmac-sha384, hmac-sha512, ed25519, ecdsa-p256-sha256 or ecdsa-p384-sha384 (required)}
        {--signing : The key may sign (your own private key or secret); partner keys stay verify-only without it}
        {--file= : A file holding the material: PEM, or base64:… (otherwise a hidden prompt asks)}
        {--activate-at= : When the key becomes usable (UTC unless an offset is given)}
        {--owner-type= : Morph type or class of the model that owns the key (e.g. the partner)}
        {--owner-id= : Key of the model that owns the key}
        {--label= : A short label, bound into the key (UTF-8, at most 191 characters)}';

    protected $description = 'Import a partner or existing key into a Sentinel key ring';

    public function handle(SentinelManager $sentinel): int
    {
        $algorithm = $this->algorithmOption();

        if ($algorithm === null) {
            $this->components->error('A valid --algorithm is required: hmac-sha256, hmac-sha384, hmac-sha512, ed25519, ecdsa-p256-sha256 or ecdsa-p384-sha384.');

            return self::INVALID;
        }

        if (($this->stringOption('owner-type') !== null || $this->stringOption('owner-id') !== null) && $this->ownerOption() === null) {
            $this->components->error('The --owner-type/--owner-id model was not found.');

            return self::INVALID;
        }

        $material = $this->material();

        if ($material === null) {
            return self::INVALID;
        }

        $ring = $this->ringOption();

        try {
            $key = $sentinel->importKey(new ImportKeyRequest(
                $ring, $this->stringArgument('kid'), $algorithm, $material, (bool) $this->option('signing'),
                $this->dateOption('activate-at'), $this->ownerOption(), $this->stringOption('label'),
            ));
        } catch (SentinelException $exception) {
            $this->components->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->components->info("Imported key [{$key->ring}:{$key->keyId}] ({$key->algorithm->value}).");
        $this->components->twoColumnDetail('Status', $key->status->value);
        $this->components->twoColumnDetail('Can sign', $key->canSign ? 'yes' : 'no');

        if ($key->ownerType !== null) {
            $this->components->twoColumnDetail('Owner', "{$key->ownerType}:{$key->ownerId}");
        }

        return self::SUCCESS;
    }

    private function material(): ?string
    {
        $file = $this->stringOption('file');

        if ($file !== null) {
            $contents = is_file($file) && is_readable($file) && filesize($file) <= self::MAX_FILE_BYTES ? file_get_contents($file) : false;

            if (! is_string($contents) || trim($contents) === '') {
                $this->components->error('The --file is missing, unreadable, empty or larger than 64 KB.');

                return null;
            }

            return $contents;
        }

        if (! $this->input->isInteractive()) {
            $this->components->error('Pass the material with --file (PEM or base64:…); it is never read from an argument.');

            return null;
        }

        $secret = $this->secret('Key material (base64:…; use --file for PEM)');

        if (! is_string($secret) || trim($secret) === '') {
            $this->components->error('No key material was given.');

            return null;
        }

        return $secret;
    }
}
