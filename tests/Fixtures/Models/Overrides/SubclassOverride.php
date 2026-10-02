<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Overrides;

/**
 * Overrides save() and delete() in a subclass and calls parent:: — the parent's methods are
 * the sealed ones of HasSeals, so every write stays sealed.
 */
final class SubclassOverride extends SealedBase
{
    /**
     * @param  array<string, mixed>  $options
     */
    public function save(array $options = []): bool
    {
        $this->name = strtoupper((string) $this->name);

        return parent::save($options);
    }

    public function delete(): ?bool
    {
        return parent::delete();
    }
}
