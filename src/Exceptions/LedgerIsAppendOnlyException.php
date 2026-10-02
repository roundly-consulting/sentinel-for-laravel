<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * Ledger entries and checkpoints are append-only evidence; Eloquent refuses to change or
 * delete them.
 */
final class LedgerIsAppendOnlyException extends SentinelException
{
    public static function update(string $table): self
    {
        return new self("Rows of [{$table}] are append-only and cannot be updated.");
    }

    public static function delete(string $table): self
    {
        return new self("Rows of [{$table}] are append-only and cannot be deleted.");
    }
}
