<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Jobs\Middleware;

use Closure;
use Illuminate\Contracts\Queue\Job;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentCall;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyRequestInProgressException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;
use RoundlyConsulting\Sentinel\Exceptions\JobNotCompletedException;
use RoundlyConsulting\Sentinel\SentinelManager;

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
 */
final readonly class Idempotent
{
    /**
     * @throws InvalidIdempotencyKeyException for an empty or overlong key or scope
     */
    public function __construct(
        public string $key,
        public string $scope = 'jobs',
        public ?int $ttl = null,
        public int $releaseAfter = 10,
    ) {
        if ($key === '' || strlen($key) > 255 || $scope === '' || strlen($scope) > 255
            || ($ttl !== null && ($ttl < 60 || $ttl > 2592000)) || $releaseAfter < 1) {
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
            }, null, $this->ttl));
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

    private static function unfinished(object $job): bool
    {
        $queued = property_exists($job, 'job') ? $job->job : null;

        return $queued instanceof Job && ($queued->isReleased() || $queued->hasFailed());
    }
}
