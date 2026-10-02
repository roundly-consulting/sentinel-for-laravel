<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Signatures;

use RoundlyConsulting\Sentinel\Http\StructuredFields\InnerList;

/**
 * The signature a profile selected: its label, its `Signature-Input` member and the raw
 * signature bytes.
 *
 * @internal
 */
final readonly class SelectedSignature
{
    public function __construct(
        public string $label,
        public InnerList $input,
        public string $signature,
    ) {}
}
