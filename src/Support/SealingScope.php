<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Closure;

/**
 * Suspension flags (`withoutSealing`, `withoutVerification`). Bound **scoped**: Laravel drops
 * it between Octane requests and queued jobs, so a suspension can never leak into the next
 * unit of work. Nesting-safe counters, restored even when the callback throws.
 *
 * @internal
 */
final class SealingScope
{
    private int $sealingSuspended = 0;

    private int $verificationSuspended = 0;

    /**
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    public function withoutSealing(Closure $callback): mixed
    {
        $this->sealingSuspended++;

        try {
            return $callback();
        } finally {
            $this->sealingSuspended--;
        }
    }

    /**
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    public function withoutVerification(Closure $callback): mixed
    {
        $this->verificationSuspended++;

        try {
            return $callback();
        } finally {
            $this->verificationSuspended--;
        }
    }

    public function sealingSuspended(): bool
    {
        return $this->sealingSuspended > 0;
    }

    public function verificationSuspended(): bool
    {
        return $this->verificationSuspended > 0;
    }
}
