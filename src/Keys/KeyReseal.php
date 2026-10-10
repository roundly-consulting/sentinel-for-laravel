<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

/**
 * What `sentinel:key:reseal` did with one stored key: re-sealed it in the current envelope
 * format (`resealed` — or would have, in a dry run), left it alone because it already binds its
 * label (`current`), or refused it — a row that fails its integrity check (`failed`), a legacy
 * row `sentinel.keys.require_bound_label` refuses (`refused`), or a legacy row whose label is not
 * UTF-8 and so cannot be bound (`unbindable`; only SQLite stores one). The label is the one bound
 * (or about to be, or that cannot be); never shown for a row that fails its integrity check,
 * whose label nothing vouches for.
 *
 * @internal
 */
final readonly class KeyReseal
{
    public const string RESEALED = 'resealed';

    public const string CURRENT = 'current';

    public const string FAILED = 'failed';

    public const string REFUSED = 'refused';

    public const string UNBINDABLE = 'unbindable';

    public function __construct(
        public string $ring,
        public string $keyId,
        public string $outcome,
        public ?string $label = null,
    ) {}

    /**
     * Whether the row failed its integrity check — under `require_bound_label` a legacy row does.
     */
    public function failsIntegrity(): bool
    {
        return $this->outcome === self::FAILED || $this->outcome === self::REFUSED;
    }
}
