<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * A nonce Sentinel issued (consumed once), or one it has seen from a client (remembered to
 * refuse a replay).
 */
enum NonceKind: string
{
    use Helpers;

    case Issued = 'issued';
    case Seen = 'seen';
}
