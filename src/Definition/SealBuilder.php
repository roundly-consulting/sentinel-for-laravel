<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Definition;

/**
 * Handed to `defineSeals()`: declare named seals; the first one is the default.
 */
final class SealBuilder
{
    /** @var list<SealDefinitionBuilder> */
    private array $seals = [];

    public function seal(string $name): SealDefinitionBuilder
    {
        $seal = new SealDefinitionBuilder($name);
        $this->seals[] = $seal;

        return $seal;
    }

    /**
     * @internal
     *
     * @return list<SealDefinitionBuilder>
     */
    public function declared(): array
    {
        return $this->seals;
    }
}
