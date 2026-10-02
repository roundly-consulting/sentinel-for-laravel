<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\UuidDocument;

it('seals UUID-keyed models through uuid morph columns', function (): void {
    $document = UuidDocument::query()->create(['title' => 'Contract']);

    expect(Sentinel::verify($document)->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($document)->sealableId)->toBe($document->id)
        ->and(Schema::getColumnType('sentinel_seals', 'sealable_id'))->not->toBe('integer');

    DB::table('uuid_documents')->where('id', $document->id)->update(['title' => 'Forged']);

    expect(Sentinel::verify($document)->changedAttributes)->toBe(['a:title']);
});
