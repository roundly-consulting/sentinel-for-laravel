<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The Eloquent write a sealable model is performing.
 */
enum PersistOperation: string
{
    use Helpers;

    case Save = 'save';
    case Delete = 'delete';
    case Increment = 'increment';
}
