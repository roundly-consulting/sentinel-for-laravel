<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReadsOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotateKeyRequest;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * Rotate a ring's signing key. Database: a new active key, the old one verify-only. Config:
 * prints the new key lines and the updated verify-only list.
 */
final class KeyRotateCommand extends Command
{
    use ReadsOptions;

    protected $signature = 'sentinel:key:rotate
        {--ring= : The key ring (default: sentinel.keys.default_ring)}
        {--algorithm= : The new key\'s algorithm (default: the current key\'s)}
        {--activate-at= : When the new database key starts signing (UTC unless an offset is given)}';

    protected $description = 'Rotate a Sentinel key ring';

    public function handle(SentinelManager $sentinel): int
    {
        $algorithm = $this->algorithmOption();

        if ($this->stringOption('algorithm') !== null && $algorithm === null) {
            $this->components->error('Unknown --algorithm.');

            return self::FAILURE;
        }

        try {
            $result = $sentinel->rotateKey(new RotateKeyRequest($this->ringOption(), $algorithm, $this->dateOption('activate-at')));
        } catch (SentinelException $exception) {
            $this->components->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->components->info("New signing key [{$result->current->ring}:{$result->current->keyId}] ({$result->current->algorithm->value}).");

        if ($result->previous !== null) {
            $this->line("Previous key [{$result->previous->keyId}] is now verify-only.");
        }

        if ($result->envSnippet !== null) {
            $this->components->warn('Treat these lines as secrets: replace the environment values — never commit or log them.');
            foreach (explode("\n", $result->envSnippet) as $line) {
                $this->line($line);
            }
        }

        return self::SUCCESS;
    }
}
