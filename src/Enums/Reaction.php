<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * What verify-on-retrieve does when a model is not intact.
 */
enum Reaction: string
{
    use Helpers;

    case Throw = 'throw';
    case Event = 'event';
    case Log = 'log';
}
