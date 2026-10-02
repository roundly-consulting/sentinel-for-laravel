<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;

return new class extends Migration
{
    public function getConnection(): ?string
    {
        $connection = config('sentinel.database.connection');

        return is_string($connection) && $connection !== '' ? $connection : null;
    }

    public function up(): void
    {
        $actor = KeyType::fromConfig('sentinel.actor_key_type');

        Schema::create('sentinel_keys', function (Blueprint $table) use ($actor): void {
            $table->id();
            $table->string('ring', 64);
            $table->string('kid', 64);
            $table->string('algorithm', 32);
            // The manual state; the effective status also folds in the dates and revocation list.
            $table->string('status', 16);
            // The encrypted JCS envelope — authoritative; the plain columns exist for querying.
            $table->text('envelope');
            $table->dateTime('activates_at', 6);
            $table->dateTime('signs_until', 6)->nullable();
            $table->dateTime('verifies_until', 6)->nullable();
            $table->dateTime('revoked_at', 6)->nullable();
            $table->text('revocation_reason')->nullable();
            $table->string('label', 191)->nullable();
            $table->morphKey('owner', $actor, true);
            $table->dateTime('created_at', 6)->nullable();
            $table->dateTime('updated_at', 6)->nullable();
            $table->unique(['ring', 'kid'], 'sentinel_keys_ring_kid_unique');
            $table->index(['ring', 'status', 'activates_at'], 'sentinel_keys_signing_idx');
        });
    }
};
