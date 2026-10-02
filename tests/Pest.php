<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use PHPUnit\Framework\ExpectationFailedException;
use Psr\Http\Message\RequestInterface;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;
use RoundlyConsulting\Sentinel\Tests\KeyTypes\UuidKeyTestCase;
use RoundlyConsulting\Sentinel\Tests\TestCase;
use RoundlyConsulting\Testing\Database\DriverMatrix;

// Explicit paths, not ->in(__DIR__): the KeyTypes directory runs on its own base case (the
// morph key type is fixed at migrate time), and Pest binds one test case per directory.
// Pure/ needs no application at all (thousands of codec cases), so it binds none.
uses(TestCase::class)->in('ArchTest.php', 'ConfigContractTest.php', 'Feature', 'Unit', 'RealEngine', 'Property', 'Perf');
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
 * impossible on that engine, which the caller asserts instead. Only that refusal counts
 * (SQLSTATE class 22 "data exception", MySQL 1292 / 1366); any other failure is rethrown.
 */
function corrupt(Closure $write): bool
{
    try {
        $write();

        return true;
    } catch (QueryException $exception) {
        $state = (string) ($exception->errorInfo[0] ?? '');
        $code = (int) ($exception->errorInfo[1] ?? 0);

        if (DriverMatrix::driver() === 'sqlite' || ! (str_starts_with($state, '22') || in_array($code, [1292, 1366], true))) {
            throw $exception;
        }

        expect(DriverMatrix::driver())->toBeIn(['pgsql', 'mysql', 'mariadb']);

        return false;
    }
}

const PARTNER_SECRET = 'base64:cGFydG5lci1zaGFyZWQtc2VjcmV0LTMyLWJ5dGVzLWxvbmctZm9yLWhtYWM=';

/**
 * An http ring on the config driver with one partner key.
 */
function partnerRing(string $kid = 'partner', Algorithm $algorithm = Algorithm::HmacSha256, string $material = PARTNER_SECRET): void
{
    config()->set('sentinel.keys.rings.http.driver', 'config');
    config()->set('sentinel.keys.rings.http.key_id', $kid);
    config()->set('sentinel.keys.rings.http.algorithm', $algorithm->value);
    config()->set('sentinel.keys.rings.http.key', $material);
    app(KeyStoreManager::class)->flush();
}

/**
 * The PSR-7 request as Laravel would receive it.
 */
function received(RequestInterface $psr, array $server = []): Request
{
    $uri = $psr->getUri();
    $server += [
        'REQUEST_METHOD' => $psr->getMethod(),
        'REQUEST_URI' => $uri->getPath().($uri->getQuery() === '' ? '' : '?'.$uri->getQuery()),
        'QUERY_STRING' => $uri->getQuery(),
        'HTTP_HOST' => $uri->getHost().($uri->getPort() === null ? '' : ':'.$uri->getPort()),
        'HTTPS' => $uri->getScheme() === 'https' ? 'on' : 'off',
        'SERVER_PORT' => $uri->getPort() ?? ($uri->getScheme() === 'https' ? 443 : 80),
    ];

    foreach ($psr->getHeaders() as $name => $values) {
        $key = strtoupper(str_replace('-', '_', (string) $name));
        $server[in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true) ? $key : 'HTTP_'.$key] = implode(', ', $values);
    }

    $body = (string) $psr->getBody();

    return new Request([], [], [], [], [], $server, $body);
}

function signedPartnerRequest(?SigningOptions $options = null, string $uri = 'https://api.example.com/events?b=2&a=1', string $body = '{"event":"paid"}', array $headers = ['Content-Type' => 'application/json']): RequestInterface
{
    return Sentinel::signatures()->sign(new PsrRequest('POST', $uri, $headers, $body), 'partner', $options);
}

/**
 * A fake assertion fails with this message.
 */
function fails(Closure $assertion, string $message): void
{
    expect($assertion)->toThrow(ExpectationFailedException::class, $message);
}

/**
 * How often each outcome of a race occurred, by outcome.
 *
 * @param  list<string>  $outcomes
 * @return array<string, int>
 */
function tally(array $outcomes): array
{
    $counts = array_count_values($outcomes);
    ksort($counts);

    return $counts;
}
