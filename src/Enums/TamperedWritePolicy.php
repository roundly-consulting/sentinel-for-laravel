<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * What an Eloquent write does when the model is not intact before it (plan §4.5.4): refuse
 * (the default — nothing is written), reseal (write, re-seal, audit the previous status in the
 * ledger) or skip (write and leave the seal as it was).
 */
enum TamperedWritePolicy: string
{
    use Helpers;

    case Refuse = 'refuse';
    case Reseal = 'reseal';
    case Skip = 'skip';
}
