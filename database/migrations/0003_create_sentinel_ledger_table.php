<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;

/**
 * The append-only seal history. Every entry carries its own MAC over the audit fields.
 */
return new class extends Migration
{
    public function up(): void
    {
        $sealable = KeyType::fromConfig('sentinel.key_type');
        $actor = KeyType::fromConfig('sentinel.actor_key_type');

        Schema::create('sentinel_ledger', function (Blueprint $table) use ($sealable, $actor): void {
            $table->id();
            $table->morphKey('sealable', $sealable);
            $table->string('seal', 64);
            $table->string('event', 16);
            $table->unsignedBigInteger('version');
            $table->string('ring', 64);
            $table->string('key_id', 64);
            $table->string('algorithm', 32);
            // Null for tombstones (deleted / unsealed).
            $table->string('seal_mac', 192)->nullable();
            $table->string('previous_digest', 64)->nullable();
            $table->jsonb('changed')->nullable();
            $table->string('previous_status', 32)->nullable();
            $table->morphKey('actor', $actor, true);
            $table->text('reason')->nullable();
            $table->string('entry_mac', 192);
            $table->dateTime('occurred_at', 6);
            $table->foreignId('checkpoint_id')->nullable()->constrained('sentinel_checkpoints')->restrictOnDelete();
            $table->unique(['sealable_type', 'sealable_id', 'seal', 'version'], 'sentinel_ledger_version_unique');
            $table->index(['checkpoint_id', 'id'], 'sentinel_ledger_checkpoint_idx');
            $table->index('occurred_at', 'sentinel_ledger_occurred_idx');
        });
    }
};
