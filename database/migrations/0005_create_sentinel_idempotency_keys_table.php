<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Idempotency keys — only a digest of (scope, route, key), never the key itself. The unique
 * digest turns two concurrent first requests into one owner and one 409.
 */
return new class extends Migration
{
    public function getConnection(): ?string
    {
        $connection = config('sentinel.database.connection');

        return is_string($connection) && $connection !== '' ? $connection : null;
    }

    public function up(): void
    {
        Schema::create('sentinel_idempotency_keys', function (Blueprint $table): void {
            $table->id();
            $table->string('key_digest', 64)->unique('sentinel_idem_key_unique');
            $table->string('scope', 255);
            $table->string('fingerprint', 64);
            $table->string('status', 16);
            $table->string('owner_token', 64);
            $table->dateTime('locked_until', 6);
            $table->unsignedSmallInteger('response_status')->nullable();
            // The stored response, encrypted by default.
            $table->longText('response')->nullable();
            $table->boolean('replayable')->default(true);
            $table->dateTime('completed_at', 6)->nullable();
            $table->dateTime('expires_at', 6);
            $table->dateTime('created_at', 6)->nullable();
            $table->dateTime('updated_at', 6)->nullable();
            $table->index('expires_at', 'sentinel_idem_expires_idx');
        });
    }
};
