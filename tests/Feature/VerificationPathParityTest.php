<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanOptions;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\TamperDetected;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Rules\IntactSeal;

/**
 * §10 item 25 / fleet theme 1: one verifier behind every path. Every status fixture reaches
 * the same verdict through the API, the handle, the trait, verifyAll/verifyMany, the
 * collection macro, the scan, verify-on-retrieve, the pre-write check — and the same
 * pass/fail through the middleware and the validation rule. (Retrieve skips the ledger check
 * by default to save a query per model; it is switched on here so the paths are comparable.)
 */
it('reaches the same verdict through every verification path', function (Closure $tamper, VerificationStatus $status): void {
    Event::fake([TamperDetected::class]);
    $class = definedBy(static fn ($seals) => $seals->seal('parity')->attributes('number', 'amount')->verifyOnRetrieve(Reaction::Report));
    $model = $class::query()->create(['number' => 'P-1', 'amount' => '5.00']);
    Route::bind('record', static fn (string $value): Model => $class::query()->findOrFail($value));
    Route::get('/parity/{record}', static fn (): string => 'ok')->middleware([SubstituteBindings::class, 'sentinel.verified:record']);
    config()->set('app.debug', false);
    config()->set('sentinel.verification.retrieve_checks_ledger', true);

    $tamper($model);
    Event::fake([TamperDetected::class]);

    $fresh = $class::query()->findOrFail($model->getKey());
    $retrieved = Event::dispatched(TamperDetected::class, static fn (TamperDetected $event): bool => $event->context === VerificationContext::Retrieve)->first()[0] ?? null;
    $scan = Sentinel::scan(new ScanOptions([$class]));

    $paths = [
        'verify' => Sentinel::verify($fresh)->status,
        'handle' => Sentinel::for($fresh)->verify()->status,
        'trait' => $fresh->verifySeal()->status,
        'verifyAll' => Sentinel::verifyAll($fresh)->results[0]->status,
        'verifyMany' => Sentinel::verifyMany([$fresh])->results[0]->status,
        'macro' => $class::query()->get()->verifySeals()->results[0]->status,
        'scan' => $scan->counts[0]->status,
        'retrieve' => $retrieved instanceof TamperDetected ? $retrieved->status : VerificationStatus::Intact,
    ];

    try {
        $fresh->update(['note' => 'write']);
        $paths['pre-write'] = VerificationStatus::Intact;
    } catch (TamperedModelException $exception) {
        $paths['pre-write'] = $exception->result()?->status;
    }

    $passes = [
        'middleware' => $this->get('/parity/'.$model->getKey())->status() === 200,
        'rule' => Validator::make(['r' => $model->getKey()], ['r' => [new IntactSeal($class)]])->passes(),
    ];

    expect(array_values(array_unique(array_map(static fn (?VerificationStatus $s): ?string => $s?->value, $paths))))->toBe([$status->value])
        ->and(array_values(array_unique($passes)))->toBe([$status->isIntact()]);
})->with([
    'intact' => [static fn (): null => null, VerificationStatus::Intact],
    'tampered' => [static fn (Model $m) => DB::table('invoices')->where('id', $m->getKey())->update(['amount' => '0.00']), VerificationStatus::Tampered],
    'missing' => [static fn (Model $m) => Seal::query()->where('sealable_id', $m->getKey())->delete(), VerificationStatus::Missing],
    'stale' => [static function (Model $m): void {
        $old = Seal::query()->where('sealable_id', $m->getKey())->firstOrFail()->getAttributes();
        $m->update(['note' => 'reseal', 'number' => 'P-2']);
        DB::table('invoices')->where('id', $m->getKey())->update(['number' => 'P-1']);
        Seal::query()->where('sealable_id', $m->getKey())->toBase()->update($old);
    }, VerificationStatus::Stale],
    'malformed' => [static fn (Model $m) => Seal::query()->where('sealable_id', $m->getKey())->toBase()->update(['format' => 9]), VerificationStatus::Malformed],
    'algorithm mismatch' => [static fn (Model $m) => Seal::query()->where('sealable_id', $m->getKey())->toBase()->update(['algorithm' => 'ed25519']), VerificationStatus::AlgorithmMismatch],
    'unknown key' => [static fn (Model $m) => Seal::query()->where('sealable_id', $m->getKey())->toBase()->update(['key_id' => 'nope']), VerificationStatus::UnknownKey],
    'revoked key' => [static fn () => config()->set('sentinel.keys.revoked', 'default:test-default'), VerificationStatus::RevokedKey],
]);
