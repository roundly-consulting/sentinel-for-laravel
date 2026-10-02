<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Support;

use Closure;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Testing\Database\DriverMatrix;
use Throwable;

/**
 * Real concurrency for the real-engine legs: forked children, each on its own database
 * session (never the parent's connection, which may be inside an open transaction). A
 * child reports one line and is SIGKILLed — no shutdown handlers, destructors or teardown.
 */
final class Forks
{
    public static function available(): bool
    {
        return DriverMatrix::driver() !== 'sqlite' && function_exists('pcntl_fork') && function_exists('posix_kill');
    }

    /**
     * @param  Closure(int $racer): string  $work
     * @return list<string>
     */
    public static function run(int $racers, Closure $work): array
    {
        $files = [];
        $pids = [];

        for ($i = 0; $i < $racers; $i++) {
            $file = (string) tempnam(sys_get_temp_dir(), 'sentinel-fork-');
            $pid = pcntl_fork();

            if ($pid === 0) {
                $outcome = 'error';

                try {
                    config()->set('database.connections.racer', DriverMatrix::connectionConfig(DriverMatrix::driver()));
                    DB::setDefaultConnection('racer');
                    app()->forgetScopedInstances();

                    $outcome = $work($i);
                } catch (Throwable $exception) {
                    $outcome = 'error: '.$exception::class.': '.$exception->getMessage();
                }

                file_put_contents($file, $outcome);
                posix_kill(posix_getpid(), SIGKILL);
            }

            $files[] = $file;
            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = array_map(static fn (string $file): string => (string) file_get_contents($file), $files);
        array_map(unlink(...), $files);

        return $outcomes;
    }
}
