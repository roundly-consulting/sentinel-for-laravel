<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * What ledger verification found. Every kind except `backlog` and `anchor_unreachable` is an
 * integrity violation (and fires `LedgerIntegrityViolated`).
 */
enum LedgerFindingKind: string
{
    use Helpers;

    case CheckpointGap = 'checkpoint_gap';
    case CheckpointInvalid = 'checkpoint_invalid';
    case CheckpointMismatch = 'checkpoint_mismatch';
    case ChainBroken = 'chain_broken';
    case AnchorAhead = 'anchor_ahead';
    case AnchorMismatch = 'anchor_mismatch';
    case AnchorInvalid = 'anchor_invalid';
    case AnchorUnreachable = 'anchor_unreachable';
    case EntryInvalid = 'entry_invalid';
    case EntityDeleted = 'entity_deleted';
    case SealRolledBack = 'seal_rolled_back';
    case SealMissing = 'seal_missing';
    case Backlog = 'backlog';

    public function isViolation(): bool
    {
        return $this !== self::Backlog && $this !== self::AnchorUnreachable;
    }
}
