<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Overrides;

use Illuminate\Database\Eloquent\Model;

/**
 * A subclass that skips the sealed save() and delete() of its parent and calls Eloquent's
 * own — its writes would bypass sealing.
 */
final class SubclassBypass extends SealedBase
{
    /**
     * @param  array<string, mixed>  $options
     */
    public function save(array $options = []): bool
    {
        return Model::save($options);
    }

    public function delete(): ?bool
    {
        return Model::delete();
    }
}
