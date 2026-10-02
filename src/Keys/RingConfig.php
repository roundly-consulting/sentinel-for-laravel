<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use RoundlyConsulting\Sentinel\Enums\Algorithm;
use SensitiveParameter;

/**
 * One validated `sentinel.keys.rings.<ring>` section.
 *
 * @internal
 */
final readonly class RingConfig
{
    /**
     * @param  list<Algorithm>  $algorithms
     * @param  list<string>  $drivers
     */
    public function __construct(
        public string $name,
        public string $driver,
        public array $algorithms,
        public ?string $keyId,
        public Algorithm $algorithm,
        #[SensitiveParameter] public ?string $key,
        public ?string $publicKey,
        #[SensitiveParameter] public string $previous,
        public array $drivers,
    ) {}

    public function allows(Algorithm $algorithm): bool
    {
        return in_array($algorithm, $this->algorithms, true);
    }

    /**
     * @return array<string, string|null>
     */
    public function __debugInfo(): array
    {
        return ['name' => $this->name, 'driver' => $this->driver, 'keyId' => $this->keyId, 'key' => '[redacted]', 'previous' => '[redacted]'];
    }
}
