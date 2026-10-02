<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Eloquent\SoftDeletingScope;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * Load the model a stored morph type and id name (a key's owner, an event's sealable):
 * morph-map aware, with verify-on-retrieve suspended — a listener loading exactly the
 * tampered row must not throw — and null when the type or the row no longer resolves.
 *
 * @internal
 */
final class MorphedModel
{
    public static function find(?string $type, int|string|null $id, bool $withTrashed = false): ?Model
    {
        if ($type === null || $type === '' || $id === null) {
            return null;
        }

        $class = Relation::getMorphedModel($type) ?? $type;

        if (! class_exists($class) || ! is_subclass_of($class, Model::class)) {
            return null;
        }

        return app(SentinelManager::class)->withoutVerification(static function () use ($class, $id, $withTrashed): ?Model {
            $query = $class::query();

            return ($withTrashed ? $query->withoutGlobalScope(SoftDeletingScope::class) : $query)->whereKey($id)->first();
        });
    }
}
