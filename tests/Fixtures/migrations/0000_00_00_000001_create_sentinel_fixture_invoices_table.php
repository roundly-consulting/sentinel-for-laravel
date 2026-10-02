<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('invoices', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('tenant_id')->default(1);
            $table->unsignedBigInteger('customer_id')->nullable();
            $table->string('number')->nullable();
            $table->string('currency', 3)->default('EUR');
            $table->decimal('amount', 12, 2)->default(0);
            $table->string('status')->default('draft');
            $table->boolean('paid')->default(false);
            $table->date('due_on')->nullable();
            $table->json('meta')->nullable();
            $table->text('secret')->nullable();
            // A column only the database fills: sealed through the read-back.
            $table->string('region', 8)->default('eu');
            $table->string('note')->nullable();
            $table->timestamps();
            $table->softDeletes();
        });

        Schema::create('invoice_lines', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('invoice_id');
            $table->string('sku');
            $table->unsignedInteger('quantity');
        });

        Schema::create('plain_records', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->integer('count')->nullable();
            $table->boolean('flag')->nullable();
            $table->string('code')->nullable();
            $table->float('ratio')->nullable();
            $table->dateTime('happened_at', 6)->nullable();
            $table->timestamps();
        });

        Schema::create('uuid_documents', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('title');
            $table->timestamps();
        });
    }
};
