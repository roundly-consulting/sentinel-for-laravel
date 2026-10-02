<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use RoundlyConsulting\Enums\Helpers;

/**
 * What a key is MACing/signing. HMAC keys derive a distinct HKDF subkey per purpose; signing
 * keys rely on the documents' distinct `v` members for separation.
 *
 * @internal
 */
enum Purpose: string
{
    use Helpers;

    /** Seal documents (`sentinel.seal/1`). */
    case Seal = 'seal';

    /** Ledger entries, checkpoints and anchors. */
    case Ledger = 'ledger';
}
