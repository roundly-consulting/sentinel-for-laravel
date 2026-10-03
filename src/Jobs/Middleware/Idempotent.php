<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Jobs\Middleware;

use Closure;
use Illuminate\Contracts\Queue\Job;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentCall;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyRequestInProgressException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;
use RoundlyConsulting\Sentinel\Exceptions\JobNotCompletedException;
use RoundlyConsulting\Sentinel\Idempotency\RunLimits;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Queue-job middleware: run a job at most once per key — a webhook redelivered as a second
 * job, a double dispatch — beyond what `ShouldBeUnique` (only while queued) and
 * `WithoutOverlapping` (only concurrently) cover.
 *
 *     public function middleware(): array
 *     {
 *         return [new Idempotent("stripe:{$this->event->id}", scope: 'webhooks')];
 *     }
 *
 * A duplicate completes without running. While the first run is still in flight, a duplicate
 * is released back onto the queue (after `retryAfter`, at least `releaseAfter` seconds). A
 * job that throws — or releases or fails itself — gives the key back, so its retries run.
 * Runs through `SentinelManager::runIdempotent()`, so `Sentinel::fake()` records it.
 *
 * A running job holds its key for a lease, past which a duplicate takes the key over (the
 * first run is presumed dead). The lease therefore covers the job's longest run: the given
 * `lease`, else the job's own `$timeout` (the worker kills it then), else its queue
 * connection's `retry_after` (Laravel redelivers a job still running after it), never less
 * than `idempotency.lock_seconds` and at most 86 400 seconds.
 */
final readonly class Idempotent
{
    /**
     * @throws InvalidIdempotencyKeyException for an empty or overlong key or scope, a TTL
     *                                        outside 60–2 592 000 seconds, a lease outside
     *                                        1–86 400 seconds or a release delay < 1
     */
    public function __construct(
        public string $key,
        public string $scope = 'jobs',
        public ?int $ttl = null,
        public int $releaseAfter = 10,
        public ?int $lease = null,
    ) {
        RunLimits::check($key, $scope, $ttl, $lease);

        if ($releaseAfter < 1) {
            throw InvalidIdempotencyKeyException::make();
        }
    }

    public function handle(object $job, Closure $next): mixed
    {
        try {
            app(SentinelManager::class)->runIdempotent(new IdempotentCall($this->key, $this->scope, static function () use ($job, $next): null {
                $next($job);

                // A job that released or failed itself did not complete: give the key back.
                if (self::unfinished($job)) {
                    throw JobNotCompletedException::make();
                }

                return null;
            }, null, $this->ttl, $this->lease ?? self::leaseFor($job)));
        } catch (IdempotencyRequestInProgressException $exception) {
            if (! method_exists($job, 'release')) {
                throw $exception;
            }

            $job->release(max($exception->retryAfterSeconds(), $this->releaseAfter));
        } catch (JobNotCompletedException) {
            // Released or failed by the job itself: the queue retries (or fails) it as usual.
        }

        return null;
    }

    /**
     * The longest the job can run: its own timeout, else its connection's `retry_after`.
     */
    private static function leaseFor(object $job): int
    {
        $timeout = property_exists($job, 'timeout') && is_int($job->timeout) && $job->timeout > 0 ? $job->timeout : null;
        $queued = property_exists($job, 'job') ? $job->job : null;
        $connection = $queued instanceof Job ? $queued->getConnectionName() : (property_exists($job, 'connection') && is_string($job->connection) ? $job->connection : config('queue.default'));
        $retryAfter = is_string($connection) ? config("queue.connections.{$connection}.retry_after") : null;
        $longest = $timeout ?? (is_numeric($retryAfter) ? (int) $retryAfter : 0);

        return min(RunLimits::MAX_LEASE, max(Settings::idempotencyLockSeconds(), $longest));
    }

    private static function unfinished(object $job): bool
    {
        $queued = property_exists($job, 'job') ? $job->job : null;

        return $queued instanceof Job && ($queued->isReleased() || $queued->hasFailed());
    }
}
