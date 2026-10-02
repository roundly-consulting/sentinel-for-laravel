<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Where a verification came from (carried in results and events).
 */
enum VerificationContext: string
{
    use Helpers;

    case Api = 'api';
    case Middleware = 'middleware';
    case Retrieve = 'retrieve';
    case Command = 'command';
    case Rule = 'rule';
    case Collection = 'collection';
    case Write = 'write';
}
