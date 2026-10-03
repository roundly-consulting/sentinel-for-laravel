<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\UuidDocument;
use RoundlyConsulting\Testing\Database\DriverMatrix;

it('seals UUID-keyed models through uuid morph columns', function (): void {
    $document = UuidDocument::query()->create(['title' => 'Contract']);

    expect(Sentinel::verify($document)->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($document)->sealableId)->toBe($document->id)
        ->and(Schema::getColumnType('sentinel_seals', 'sealable_id'))->not->toBe('integer');

    DB::table('uuid_documents')->where('id', $document->id)->update(['title' => 'Forged']);

    expect(Sentinel::verify($document)->changedAttributes)->toBe(['a:title']);
});

it('holds integer keys under key_type = uuid on MySQL and SQLite, never on PostgreSQL (dual-review O-39)', function (): void {
    // PostgreSQL's uuid morph column is a native `uuid`: a mixed fleet there needs a string
    // morph id (installation.md) — the uuid type refuses an integer key outright.
    if (DriverMatrix::driver() === 'pgsql') {
        expect(fn () => invoice())->toThrow(QueryException::class, 'uuid');

        return;
    }

    expect(Sentinel::verify(invoice())->status)->toBe(VerificationStatus::Intact);
});
