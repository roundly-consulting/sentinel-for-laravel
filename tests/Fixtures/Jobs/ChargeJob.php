<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use RoundlyConsulting\Sentinel\Jobs\Middleware\Idempotent;
use RuntimeException;

/**
 * A queued job guarded by the Idempotent middleware; `$behaviour` scripts each run.
 */
final class ChargeJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;

    public static int $runs = 0;

    /** @var list<string> what each run does: complete, throw, release or fail */
    public static array $behaviour = [];

    public function __construct(public readonly string $eventId) {}

    /**
     * @return list<object>
     */
    public function middleware(): array
    {
        return [new Idempotent("stripe:{$this->eventId}", scope: 'webhooks')];
    }

    public function handle(): void
    {
        self::$runs++;

        match (array_shift(self::$behaviour) ?? 'complete') {
            'throw' => throw new RuntimeException('gateway down'),
            'release' => $this->release(30),
            'fail' => $this->fail(new RuntimeException('declined')),
            default => null,
        };
    }
}
