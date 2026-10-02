<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Install;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\File;
use RoundlyConsulting\Sentinel\Tests\TestCase;

/**
 * `sentinel:install` publishes into the host's config/ and database/: here a throwaway
 * directory per test, set before the providers boot (their publish destinations are fixed
 * then) — never the shared testbench skeleton other parallel processes load config from.
 */
abstract class InstallTestCase extends TestCase
{
    private string $sandbox = '';

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $this->sandbox = sys_get_temp_dir().'/sentinel-install-'.bin2hex(random_bytes(6));
        File::ensureDirectoryExists($this->sandbox.'/config');
        File::ensureDirectoryExists($this->sandbox.'/database/migrations');

        $app->useConfigPath($this->sandbox.'/config');
        $app->useDatabasePath($this->sandbox.'/database');
    }

    protected function tearDown(): void
    {
        if ($this->sandbox !== '') {
            File::deleteDirectory($this->sandbox);
        }

        parent::tearDown();
    }
}
