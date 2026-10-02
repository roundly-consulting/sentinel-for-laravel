<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use SensitiveParameter;

/**
 * The result of resolving `ring:kid`: the key, or why there is none (`not_found`,
 * `integrity`).
 *
 * @internal
 */
final readonly class KeyLookup
{
    public const string NOT_FOUND = 'not_found';

    public const string INTEGRITY = 'integrity';

    public function __construct(
        #[SensitiveParameter] public ?SealingKey $key,
        public ?string $failure = null,
    ) {}
}
