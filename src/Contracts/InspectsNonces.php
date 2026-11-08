<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Contracts;

use Carbon\CarbonImmutable;

/**
 * An optional {@see NonceStore} capability: look a remembered client nonce up without recording
 * it. `Sentinel::signatures()->verifyDeferred()` needs it to refuse a replay before the
 * consumer commits; the built-in `database` and `cache` stores implement it. A store bound
 * without it keeps working for everything else — a deferred verification refuses to run.
 */
interface InspectsNonces
{
    /**
     * A record of this nonce, remembered with `remember()`, is still live at `now`. Reads
     * only: a true here is a replay, a false is no promise — the atomic `remember()` decides.
     */
    public function seen(string $purpose, string $digest, CarbonImmutable $now): bool;
}
