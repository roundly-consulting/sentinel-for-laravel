<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;

/**
 * Nonces Sentinel issued (consumed once) or saw from clients (replays refused) — only their
 * SHA-256 digests.
 */
return new class extends Migration
{
    public function getConnection(): ?string
    {
        $connection = config('sentinel.database.connection');

        return is_string($connection) && trim($connection) !== '' ? $connection : null;
    }

    public function up(): void
    {
        $actor = KeyType::fromConfig('sentinel.actor_key_type');

        Schema::create('sentinel_nonces', function (Blueprint $table) use ($actor): void {
            $table->id();
            $table->string('purpose', 128);
            $table->string('digest', 64);
            $table->string('kind', 8);
            $table->morphKey('subject', $actor, true);
            $table->dateTime('expires_at', 6);
            $table->dateTime('consumed_at', 6)->nullable();
            $table->dateTime('created_at', 6);
            $table->unique(['purpose', 'digest'], 'sentinel_nonces_unique');
            $table->index('expires_at', 'sentinel_nonces_expires_idx');
        });
    }
};
