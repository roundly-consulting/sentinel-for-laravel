<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * What an idempotency store decided for an incoming key.
 */
enum IdempotencyOutcome: string
{
    use Helpers;

    /** First time (or the lease expired): run the handler. */
    case Proceed = 'proceed';

    /** Already completed: replay the stored response. */
    case Replay = 'replay';

    /** Another request holds the key right now. */
    case InProgress = 'in_progress';

    /** The key was used with a different request payload. */
    case Reused = 'reused';

    /** Completed, but the response could not be stored for replay. */
    case Unavailable = 'unavailable';
}
