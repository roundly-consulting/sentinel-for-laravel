<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Tests\TestCase;

/**
 * I-12: `sentinel:install` publishes, generates the default key when there is none and prints
 * the next steps — into a throwaway config/ and database/ ({@see InstallTestCase}).
 */
it('publishes into the sandbox, never the shared skeleton', function (): void {
    expect(config_path('sentinel.php'))->toContain('sentinel-install-')
        ->and(database_path('migrations'))->toContain('sentinel-install-');
});

it('publishes the config and the migrations, generates the missing key and prints the next steps', function (): void {
    config()->set('sentinel.keys.rings.default.key', null);
    app(KeyStoreManager::class)->flush();

    expect(Artisan::call('sentinel:install'))->toBe(0);

    $output = Artisan::output();

    expect(is_file(config_path('sentinel.php')))->toBeTrue()
        ->and(glob(database_path('migrations/*sentinel*.php')))->toHaveCount(6)
        ->and($output)->toContain('Published config/sentinel.php')->toContain('Published the migrations')
        ->toContain('key_type (sealed models)')->toContain('bigint')->toContain('before running the migrations')
        ->toContain('add these lines to your environment')->toContain('SENTINEL_KEY_ID=')->toContain('SENTINEL_KEY="base64:')
        ->toContain('php artisan migrate')->toContain('use RoundlyConsulting\\Sentinel\\Concerns\\HasSeals;')
        ->toContain("\$seals->seal('financial')")->toContain('sentinel:seal-missing')->toContain('php artisan sentinel:check')
        ->and(Key::query()->count())->toBe(0);
});

it('keeps an existing key, and running it again is harmless', function (): void {
    expect(Artisan::call('sentinel:install'))->toBe(0)
        ->and(Artisan::output())->toContain('already has a signing key')->not->toContain('SENTINEL_KEY=');

    file_put_contents(config_path('sentinel.php'), "<?php return ['edited' => true];\n");

    expect(Artisan::call('sentinel:install'))->toBe(0)
        ->and((string) file_get_contents(config_path('sentinel.php')))->toContain('edited')
        ->and(glob(database_path('migrations/*sentinel*.php')))->toHaveCount(6)
        ->and(Artisan::output())->not->toContain(TestCase::ROOT_KEY);

    expect(Artisan::call('sentinel:install', ['--force' => true]))->toBe(0)
        ->and((string) file_get_contents(config_path('sentinel.php')))->not->toContain('edited');
});

it('points a database ring at generating its key after migrating', function (): void {
    config()->set('sentinel.keys.rings.default.driver', 'database');
    app(KeyStoreManager::class)->flush();

    expect(Artisan::call('sentinel:install'))->toBe(0)
        ->and(Artisan::output())->toContain('After migrating, generate the default ring\'s key: php artisan sentinel:key:generate --database');
});

it('points a chain ring whose database half is not migrated at generating its key after migrating', function (): void {
    config()->set('sentinel.keys.rings.default.driver', 'chain');
    config()->set('sentinel.keys.rings.default.key', null);
    config()->set('database.connections.unmigrated', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
    config()->set('sentinel.database.connection', 'unmigrated');
    app(KeyStoreManager::class)->flush();

    expect(Artisan::call('sentinel:install'))->toBe(0)
        ->and(Artisan::output())->toContain('After migrating, generate the default ring\'s key: php artisan sentinel:key:generate')->not->toContain('SENTINEL_KEY=');
});

it('reports an invalid key configuration instead of failing', function (): void {
    config()->set('sentinel.keys.default_ring', 'Bad Ring');

    expect(Artisan::call('sentinel:install'))->toBe(0)
        ->and(Artisan::output())->toContain('The key configuration is not valid yet');
});
