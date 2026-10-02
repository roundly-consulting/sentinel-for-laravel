<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use Closure;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Engine\Persister;
use RoundlyConsulting\Sentinel\Enums\PersistOperation;

/**
 * The Eloquent write path of `HasSeals` (save, delete, increment, …) — through the manager,
 * so `Sentinel::fake()` sees it.
 *
 * @internal
 */
final readonly class PersistSealedModelAction
{
    public function __construct(private Persister $persister) {}

    public function execute(Model $model, Closure $write, PersistOperation $operation): mixed
    {
        return $this->persister->persist($model, $write, $operation);
    }
}
