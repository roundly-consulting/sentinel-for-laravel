<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Where a generated key goes: printed as environment lines (config) or stored encrypted in
 * `sentinel_keys` (database).
 */
enum KeyDestination: string
{
    use Helpers;

    case Config = 'config';
    case Database = 'database';
}
