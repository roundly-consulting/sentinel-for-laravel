<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * A model's `defineSeals()` does not compile. Every problem is listed at once, so a
 * definition is fixed in one pass.
 */
final class InvalidSealDefinitionException extends SentinelException
{
    /**
     * @param  list<string>  $problems
     */
    private function __construct(string $message, private readonly array $problems)
    {
        parent::__construct($message);
    }

    /**
     * @param  list<string>  $problems
     */
    public static function forClass(string $class, array $problems): self
    {
        return new self(
            "The seal definition of [{$class}] is invalid:\n  - ".implode("\n  - ", $problems),
            $problems,
        );
    }

    public static function invalidScale(int $scale, int $maximum): self
    {
        return new self("A decimal/float scale must be between 0 and {$maximum}, [{$scale}] given.", [
            "scale {$scale} is outside 0..{$maximum}",
        ]);
    }

    /**
     * @return list<string>
     */
    public function problems(): array
    {
        return $this->problems;
    }
}
