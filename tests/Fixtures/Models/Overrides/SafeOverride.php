<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Overrides;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;
use RoundlyConsulting\Sentinel\Enums\PersistOperation;

/**
 * Overrides save() and delete() the supported way: through persistSealed().
 *
 * @property string|null $name
 */
final class SafeOverride extends Model implements Sealable
{
    use HasSeals;

    protected $table = 'plain_records';

    protected $guarded = [];

    public static function defineSeals(SealBuilder $seals): void
    {
        $seals->seal('default')->attributes('name');
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public function save(array $options = []): bool
    {
        $this->name = trim((string) $this->name);

        return $this->persistSealed(fn (): bool => Model::save($options)) === true;
    }

    public function delete(): ?bool
    {
        $deleted = $this->persistSealed(fn (): ?bool => Model::delete(), PersistOperation::Delete);

        return is_bool($deleted) ? $deleted : null;
    }
}
