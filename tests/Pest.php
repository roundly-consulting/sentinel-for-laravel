<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;
use RoundlyConsulting\Sentinel\Tests\KeyTypes\UuidKeyTestCase;
use RoundlyConsulting\Sentinel\Tests\TestCase;
use RoundlyConsulting\Testing\Database\DriverMatrix;

// Explicit paths, not ->in(__DIR__): the KeyTypes directory runs on its own base case (the
// morph key type is fixed at migrate time), and Pest binds one test case per directory.
// Pure/ needs no application at all (thousands of codec cases), so it binds none.
uses(TestCase::class)->in('ArchTest.php', 'ConfigContractTest.php', 'Feature', 'Unit', 'RealEngine');
uses(UuidKeyTestCase::class)->in('KeyTypes');

/**
 * A sealed invoice (financial + identity seals).
 *
 * @param  array<string, mixed>  $attributes
 */
function invoice(array $attributes = []): Invoice
{
    return Invoice::query()->create([
        'customer_id' => 7,
        'number' => 'INV-'.random_int(1000, 9999),
        'amount' => '10.50',
        'status' => 'paid',
        'paid' => true,
        'due_on' => '2026-10-31',
        'meta' => ['channel' => 'web'],
        'secret' => 'iban-123',
        ...$attributes,
    ]);
}

/**
 * @param  array<string, mixed>  $attributes
 */
function record(array $attributes = []): PlainRecord
{
    return PlainRecord::query()->create(['name' => 'alpha', 'count' => 3, 'code' => 'A1', 'flag' => true, 'ratio' => 0.5, ...$attributes]);
}

/**
 * A throwaway sealable whose definition the test supplies.
 */
function definedBy(Closure $define): string
{
    $class = 'DefinedModel'.bin2hex(random_bytes(4));

    eval('final class '.$class.' extends '.Model::class.' implements '.Sealable::class.' {
        use '.HasSeals::class.';
        public static ?Closure $define = null;
        protected $table = "invoices";
        protected $guarded = [];
        protected $casts = ["amount" => "decimal:2", "ratio" => "float", "big" => "decimal:40"];
        public static function defineSeals('.SealBuilder::class.' $seals): void { (self::$define)($seals); }
    }');

    $class::$define = $define;

    return $class;
}

/**
 * Write a corrupt value the way an attacker with SQL access would. SQLite stores anything;
 * PostgreSQL and MySQL refuse what does not fit the column type — then the corruption is
 * impossible on that engine, which the caller asserts instead.
 */
function corrupt(Closure $write): bool
{
    try {
        $write();

        return true;
    } catch (QueryException) {
        expect(DriverMatrix::driver())->not->toBe('sqlite');

        return false;
    }
}
