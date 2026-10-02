<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;

/**
 * The current seal per (sealable, seal). The `algorithm` column is informational only —
 * verification always takes the algorithm from the key.
 */
return new class extends Migration
{
    public function up(): void
    {
        $sealable = KeyType::fromConfig('sentinel.key_type');
        $actor = KeyType::fromConfig('sentinel.actor_key_type');

        Schema::create('sentinel_seals', function (Blueprint $table) use ($sealable, $actor): void {
            $table->id();
            $table->morphKey('sealable', $sealable);
            $table->string('seal', 64);
            $table->unsignedSmallInteger('format');
            $table->string('ring', 64);
            $table->string('key_id', 64);
            $table->string('algorithm', 32);
            $table->unsignedBigInteger('version');
            $table->string('previous_digest', 64)->nullable();
            $table->string('mac', 192);
            $table->jsonb('manifest');
            $table->jsonb('field_tags')->nullable();
            $table->string('event', 16);
            $table->morphKey('sealed_by', $actor, true);
            $table->text('reason')->nullable();
            $table->dateTime('sealed_at', 6);
            $table->foreignId('ledger_entry_id')->nullable()->constrained('sentinel_ledger')->restrictOnDelete();
            $table->dateTime('created_at', 6)->nullable();
            $table->dateTime('updated_at', 6)->nullable();
            $table->unique(['sealable_type', 'sealable_id', 'seal'], 'sentinel_seals_entity_unique');
            $table->index(['ring', 'key_id'], 'sentinel_seals_key_idx');
        });
    }
};
