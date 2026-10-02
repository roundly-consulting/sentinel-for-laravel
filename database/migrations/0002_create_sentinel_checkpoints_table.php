<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Lives on the sealables' connection (it shares their transactions). Hosts with sealables on
 * several connections run 0002–0004 on each and list them in `sentinel.ledger.connections`.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sentinel_checkpoints', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('seq')->unique('sentinel_checkpoints_seq_unique');
            $table->unsignedBigInteger('first_entry_id');
            $table->unsignedBigInteger('last_entry_id');
            $table->unsignedInteger('entries');
            $table->string('root', 64);
            $table->string('previous_digest', 64)->nullable();
            $table->string('ring', 64);
            $table->string('key_id', 64);
            $table->string('algorithm', 32);
            $table->string('mac', 192);
            $table->dateTime('created_at', 6);
        });
    }
};
