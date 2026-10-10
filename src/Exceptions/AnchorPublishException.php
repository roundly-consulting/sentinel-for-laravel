<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * An anchor did not take a checkpoint. Caught by the checkpoint run, which reports it as
 * `AnchorPublishFailed`.
 */
final class AnchorPublishException extends SentinelException
{
    /**
     * The anchor holds a checkpoint the database no longer has (or has with another root):
     * that copy is the evidence of a rollback, so it is never overwritten.
     */
    public static function diverged(string $detail): self
    {
        return new self("Refused to publish the checkpoint: {$detail}. The anchor keeps its copy (was the database restored?); investigate before clearing it.");
    }

    /**
     * The store reported a failed write by returning false (a disk with `throw` off, a cache
     * store that dropped the value).
     */
    public static function notWritten(string $anchor, string $target): self
    {
        return new self("The [{$anchor}] anchor did not write [{$target}]: its store reported a failure.");
    }
}
