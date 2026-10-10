<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Psr\Http\Message\RequestInterface;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Anchors\MemoryAnchor;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;

const MATRIX_TABLES = ['invoices', 'invoice_lines', 'sentinel_checkpoints', 'sentinel_ledger', 'sentinel_seals', 'sentinel_keys'];

/**
 * @return array<string, list<array<string, mixed>>>
 */
function matrixSnapshot(): array
{
    $snapshot = [];

    foreach (MATRIX_TABLES as $table) {
        $snapshot[$table] = DB::table($table)->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all();
    }

    return $snapshot;
}

/**
 * Put every table back exactly as snapshotted (the attacker restores a backup).
 *
 * @param  array<string, list<array<string, mixed>>>  $snapshot
 */
function matrixRestore(array $snapshot): void
{
    foreach (array_reverse(MATRIX_TABLES) as $table) {
        DB::table($table)->delete();
    }

    foreach (MATRIX_TABLES as $table) {
        foreach (array_chunk($snapshot[$table], 50) as $rows) {
            DB::table($table)->insert($rows);
        }
    }
}

/**
 * Restore one invoice row and its seal rows as they were (a targeted rollback).
 *
 * @param  array<string, list<array<string, mixed>>>  $snapshot
 */
function matrixRestoreEntity(array $snapshot, Invoice $invoice): void
{
    $row = collect($snapshot['invoices'])->firstWhere('id', $invoice->id);
    DB::table('invoices')->where('id', $invoice->id)->update($row);

    foreach (collect($snapshot['sentinel_seals'])->where('sealable_id', $invoice->id) as $seal) {
        DB::table('sentinel_seals')->where('id', $seal['id'])->update($seal);
    }
}

function matrixDatabaseKey(?string $label = null): void
{
    config()->set('sentinel.keys.rings.default.driver', 'database');
    app(KeyStoreManager::class)->flush();
    Sentinel::keys()->ring()->generate(Algorithm::HmacSha256, 'db-key', label: $label);
}

/**
 * Whether Sentinel notices anything: a model that does not verify, or a ledger violation —
 * with or without the external anchor.
 *
 * @param  list<Model>  $models
 */
function matrixSees(array $models, bool $withAnchor): bool
{
    config()->set('sentinel.ledger.anchors', $withAnchor ? 'memory' : '');

    foreach ($models as $model) {
        if (array_filter(Sentinel::verifyAll($model)->results, static fn (VerificationResult $result): bool => $result->failed()) !== []) {
            return true;
        }
    }

    return ! Sentinel::verifyLedger()->clean();
}

/**
 * The §3.2 detection matrix, row by row: what DB-only storage detects and what an external
 * anchor adds. A `false` is a documented non-guarantee (§3.3), asserted as such.
 */
it('detects exactly what the threat model promises', function (Closure $attack, bool $dbOnly, bool $withAnchor): void {
    MemoryAnchor::install();

    $models = $attack();

    expect(matrixSees($models, false))->toBe($dbOnly)
        ->and(matrixSees($models, true))->toBe($withAnchor);
})->with([
    '#1 change a sealed column' => [static function (): array {
        $a = invoice();
        DB::table('invoices')->where('id', $a->id)->update(['amount' => '0.00']);

        return [$a];
    }, true, true],
    '#2 change rows feeding a computed value' => [static function (): array {
        $a = invoice();
        DB::table('invoice_lines')->insert(['invoice_id' => $a->id, 'sku' => 'X', 'quantity' => 9]);

        return [$a];
    }, true, true],
    '#3 copy values and the seal from another row' => [static function (): array {
        $a = invoice(['amount' => '1.00']);
        $b = invoice(['amount' => '9.00']);
        DB::table('invoices')->where('id', $a->id)->update(['amount' => '9.00']);
        $seal = Seal::query()->where('sealable_id', $b->id)->where('seal', 'financial')->firstOrFail();
        Seal::query()->where('sealable_id', $a->id)->where('seal', 'financial')->toBase()->update($seal->only(['mac', 'field_tags', 'sealed_at', 'version', 'previous_digest']));

        return [$a];
    }, true, true],
    '#4 re-point a seal row' => [static function (): array {
        $a = invoice();
        $b = invoice();
        Seal::query()->where('sealable_id', $b->id)->where('seal', 'financial')->delete();
        Seal::query()->where('sealable_id', $a->id)->where('seal', 'financial')->toBase()->update(['sealable_id' => $b->id]);

        return [$b];
    }, true, true],
    '#5 delete a seal row' => [static function (): array {
        $a = invoice();
        Seal::query()->where('sealable_id', $a->id)->where('seal', 'financial')->delete();

        return [$a];
    }, true, true],
    '#6 insert an unsealed row' => [static function (): array {
        Invoice::query()->insert(['number' => 'raw']);

        return [Invoice::query()->where('number', 'raw')->firstOrFail()];
    }, true, true],
    '#7 restore an older row and its older seal' => [static function (): array {
        $a = invoice(['amount' => '1.00']);
        $old = matrixSnapshot();
        $a->update(['amount' => '2.00']);
        matrixRestoreEntity($old, $a);

        return [$a];
    }, true, true],
    '#8 #7 and delete the newer ledger entries — already checkpointed' => [static function (): array {
        $a = invoice(['amount' => '1.00']);
        $old = matrixSnapshot();
        $a->update(['amount' => '2.00']);
        Sentinel::checkpoint();
        matrixRestoreEntity($old, $a);
        DB::table('sentinel_ledger')->whereNotIn('id', array_column($old['sentinel_ledger'], 'id'))->delete();

        return [$a];
    }, true, true],
    '#8 #7 and delete the newer ledger entries — inside the window' => [static function (): array {
        $a = invoice(['amount' => '1.00']);
        Sentinel::checkpoint();
        $old = matrixSnapshot();
        $a->update(['amount' => '2.00']);
        matrixRestoreEntity($old, $a);
        DB::table('sentinel_ledger')->whereNotIn('id', array_column($old['sentinel_ledger'], 'id'))->delete();

        return [$a];
    }, false, false],
    '#9 restore the whole database to an older snapshot' => [static function (): array {
        $a = invoice(['amount' => '1.00']);
        Sentinel::checkpoint();
        $old = matrixSnapshot();
        $a->update(['amount' => '2.00']);
        invoice();
        Sentinel::checkpoint();
        matrixRestore($old);

        return [$a];
    }, false, true],
    '#10 delete the checkpoint tail and its entries' => [static function (): array {
        $a = invoice(['amount' => '1.00']);
        Sentinel::checkpoint();
        $old = matrixSnapshot();
        $a->update(['amount' => '2.00']);
        Sentinel::checkpoint();
        matrixRestoreEntity($old, $a);
        DB::table('sentinel_ledger')->whereNotIn('id', array_column($old['sentinel_ledger'], 'id'))->delete();
        DB::table('sentinel_checkpoints')->whereNotIn('id', array_column($old['sentinel_checkpoints'], 'id'))->delete();

        return [$a];
    }, false, true],
    '#11 rewrite a ledger entry' => [static function (): array {
        $a = invoice();
        Sentinel::checkpoint();
        DB::table('sentinel_ledger')->where('sealable_id', $a->id)->update(['reason' => 'rewritten']);

        return [];
    }, true, true],
    '#11 rewrite a checkpoint' => [static function (): array {
        invoice();
        Sentinel::checkpoint();
        DB::table('sentinel_checkpoints')->update(['entries' => 1]);

        return [];
    }, true, true],
    '#12 delete a sealable row without a tombstone' => [static function (): array {
        $a = invoice();
        DB::table('invoices')->where('id', $a->id)->delete();

        return [];
    }, true, true],
    '#13 rewrite the stored algorithm, key id or ring of a seal' => [static function (): array {
        $a = invoice();
        $b = invoice();
        $c = invoice();
        Seal::query()->where('sealable_id', $a->id)->toBase()->update(['algorithm' => 'ed25519']);
        Seal::query()->where('sealable_id', $b->id)->toBase()->update(['key_id' => 'other']);
        Seal::query()->where('sealable_id', $c->id)->toBase()->update(['ring' => 'http']);

        return [$a, $b, $c];
    }, true, true],
    '#14 swap the columns of a database key' => [static function (): array {
        matrixDatabaseKey();
        $a = invoice();
        DB::table('sentinel_keys')->update(['algorithm' => 'hmac-sha512']);
        app(KeyStoreManager::class)->flush();

        return [$a];
    }, true, true],
    '#14 rewrite the label of a database key' => [static function (): array {
        matrixDatabaseKey('ACME billing');
        $a = invoice();
        DB::table('sentinel_keys')->update(['label' => 'Evil Corp']);
        app(KeyStoreManager::class)->flush();

        return [$a];
    }, true, true],
    '#15 restore an older database key envelope (un-revoke)' => [static function (): array {
        matrixDatabaseKey();
        $a = invoice();
        $before = DB::table('sentinel_keys')->first();
        Sentinel::keys()->ring()->revoke('db-key', 'compromised');
        DB::table('sentinel_keys')->update((array) $before);
        app(KeyStoreManager::class)->flush();

        return [$a];
    }, false, false],
    '#16 change and roll back inside the window' => [static function (): array {
        $a = invoice(['amount' => '1.00']);
        DB::table('invoices')->where('id', $a->id)->update(['amount' => '0.00']);
        DB::table('invoices')->where('id', $a->id)->update(['amount' => '1.00']);

        return [$a];
    }, false, false],
]);

it('lets the configured revocation list beat a restored key envelope (#15 mitigation)', function (): void {
    matrixDatabaseKey();
    $a = invoice();
    $before = DB::table('sentinel_keys')->first();
    Sentinel::keys()->ring()->revoke('db-key', 'compromised');
    DB::table('sentinel_keys')->update((array) $before);
    config()->set('sentinel.keys.revoked', 'default:db-key');
    app(KeyStoreManager::class)->flush();

    expect(Sentinel::verify($a)->status)->toBe(VerificationStatus::RevokedKey);
});

/**
 * §3.2 rows 17–21: the request-integrity half of the matrix (no anchor column).
 */
it('detects replayed, altered and duplicated requests', function (): void {
    config()->set('app.debug', false);
    partnerRing(material: 'base64:'.base64_encode(str_repeat("\x07\x01", 16)));

    Route::post('/signed', static fn (): string => 'ok')->middleware('sentinel.signed');
    Route::post('/orders', static fn (): string => (string) cache()->increment('orders'))->middleware('sentinel.idempotent');
    Route::get('/once', static fn (): string => 'once')->name('once')->middleware('sentinel.single-use');

    $signed = Sentinel::signatures()->sign(new PsrRequest('POST', 'https://api.example.com/signed', ['Content-Type' => 'text/plain'], 'pay 10'), 'partner');
    $server = static fn (RequestInterface $psr): array => [
        'HTTPS' => 'on', 'HTTP_HOST' => 'api.example.com', 'CONTENT_TYPE' => 'text/plain',
        'HTTP_CONTENT_DIGEST' => $psr->getHeaderLine('Content-Digest'),
        'HTTP_SIGNATURE_INPUT' => $psr->getHeaderLine('Signature-Input'), 'HTTP_SIGNATURE' => $psr->getHeaderLine('Signature'),
    ];

    // #17 replay, #18 altered body.
    $this->call('POST', 'https://api.example.com/signed', server: $server($signed), content: 'pay 10')->assertOk();
    $this->call('POST', 'https://api.example.com/signed', server: $server($signed), content: 'pay 10')->assertUnauthorized();
    $this->call('POST', 'https://api.example.com/signed', server: $server($signed), content: 'pay 99')->assertUnauthorized();

    // #19 a duplicated POST, #20 a key reused with another payload.
    $key = ['Idempotency-Key' => '"order-0001-0001-0001"'];
    $this->postJson('/orders', ['n' => 1], $key)->assertSee('1');
    $this->postJson('/orders', ['n' => 1], $key)->assertSee('1')->assertHeader('Idempotent-Replayed', 'true');
    $this->postJson('/orders', ['n' => 2], $key)->assertStatus(422);

    // #21 a single-use URL used twice.
    $url = Sentinel::nonces()->signedRoute('once');
    $this->get($url)->assertOk();
    $this->get($url)->assertForbidden();
});
