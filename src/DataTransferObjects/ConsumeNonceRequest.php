<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;
use SensitiveParameter;

/**
 * Consume a nonce: it must have been issued for this purpose (and subject), be unexpired
 * and unused.
 */
final readonly class ConsumeNonceRequest
{
    public function __construct(
        public string $purpose,
        #[SensitiveParameter] public string $value,
        public ?Model $subject = null,
    ) {}

    /**
     * @return array<string, string|null>
     */
    public function __debugInfo(): array
    {
        return ['purpose' => $this->purpose, 'value' => '[redacted]', 'subject' => $this->subject === null ? null : $this->subject->getMorphClass()];
    }
}
