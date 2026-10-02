<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Support\Settings;
use Throwable;

/**
 * Guided installation: publishes the config and the migrations, points at the key types to
 * settle before migrating, generates the default ring's key when it has none (printing the
 * environment lines — `.env` is never written) and prints the remaining steps. Running it
 * again is harmless: published files are kept unless `--force`.
 */
final class InstallCommand extends Command
{
    /** The model the next steps show. */
    private const array SNIPPET = [
        'use Illuminate\Database\Eloquent\Model;',
        'use RoundlyConsulting\Sentinel\Concerns\HasSeals;',
        'use RoundlyConsulting\Sentinel\Contracts\Sealable;',
        'use RoundlyConsulting\Sentinel\Definition\SealBuilder;',
        '',
        'class Invoice extends Model implements Sealable',
        '{',
        '    use HasSeals;',
        '',
        '    public static function defineSeals(SealBuilder $seals): void',
        '    {',
        "        \$seals->seal('financial')->attributes('customer_id', 'currency', 'amount', 'status');",
        '    }',
        '}',
    ];

    protected $signature = 'sentinel:install {--force : Overwrite published files}';

    protected $description = 'Install Sentinel: publish, generate a key, print the next steps';

    public function handle(KeyStoreManager $keys): int
    {
        $force = (bool) $this->option('force');

        foreach (['sentinel-config' => 'config/sentinel.php', 'sentinel-migrations' => 'the migrations'] as $tag => $what) {
            $this->callSilently('vendor:publish', ['--tag' => $tag, '--force' => $force]);
            $this->components->task("Published {$what}");
        }

        $this->newLine();
        $this->components->twoColumnDetail('key_type (sealed models)', self::string(config('sentinel.key_type')));
        $this->components->twoColumnDetail('actor_key_type (actors, key owners)', self::string(config('sentinel.actor_key_type')));
        $this->components->warn('Set both in config/sentinel.php (bigint, uuid or ulid) before running the migrations — they cannot change afterwards.');

        $this->key($keys);

        $this->newLine();
        $this->components->info('Next steps');
        $this->line('  1. php artisan migrate');
        $this->line('  2. Seal a model:');
        $this->newLine();

        foreach (self::SNIPPET as $line) {
            $this->line($line === '' ? '' : '     '.$line);
        }

        $this->newLine();
        $this->line('  3. php artisan sentinel:seal-missing "App\\Models\\Invoice" --reason="Initial baseline"');
        $this->line('  4. php artisan sentinel:check');

        return self::SUCCESS;
    }

    /**
     * Generate the default ring's key when it has none: environment lines for a config ring,
     * a hint for a database ring (its table does not exist before the migrations run).
     */
    private function key(KeyStoreManager $keys): void
    {
        $this->newLine();

        try {
            $ring = Settings::defaultRing();
            $driver = Settings::ring($ring)->driver;
        } catch (SentinelException $exception) {
            $this->components->warn('The key configuration is not valid yet: '.$exception->getMessage());

            return;
        }

        if ($driver === 'database') {
            $this->components->warn("After migrating, generate the default ring's key: php artisan sentinel:key:generate --database");

            return;
        }

        try {
            $keys->signingKey($ring);
            $this->components->info("The default ring [{$ring}] already has a signing key.");

            return;
        } catch (NoSigningKeyException) {
            // Generate one below.
        } catch (Throwable) {
            // A chain ring whose database half is not migrated yet.
            $this->components->warn("After migrating, generate the default ring's key: php artisan sentinel:key:generate");

            return;
        }

        $this->components->info("A key for the default ring [{$ring}] — add these lines to your environment:");
        $this->call('sentinel:key:generate', ['--ring' => $ring]);
    }

    private static function string(mixed $value): string
    {
        return is_string($value) && $value !== '' ? $value : 'bigint';
    }
}
