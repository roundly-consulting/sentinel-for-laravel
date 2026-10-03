<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Definition\Inference;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;
use RoundlyConsulting\Sentinel\Definition\SealType;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\TamperedWritePolicy;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSealDefinitionException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Tests\Fixtures\IntBacked;
use RoundlyConsulting\Sentinel\Tests\Fixtures\InvoiceStatus;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\InvoiceLine;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;

it('compiles a definition once into sorted, typed manifest fields', function (): void {
    $registry = app(DefinitionRegistry::class);
    $seals = $registry->for(Invoice::class);
    $financial = $seals->get();

    expect($seals->names())->toBe(['financial', 'identity'])
        ->and($seals->default)->toBe('financial')
        ->and($registry->for(new Invoice))->toBe($seals)
        ->and($financial->manifest())->toBe([
            ['a:amount', 'dec:2'], ['a:currency', 'auto'], ['a:customer_id', 'auto'], ['a:due_on', 'date'],
            ['a:paid', 'bool'], ['a:region', 'auto'], ['a:status', 'str'], ['c:lines', 'auto'],
        ])
        ->and($financial->columns())->toBe(['amount', 'currency', 'customer_id', 'due_on', 'paid', 'region', 'status'])
        ->and($financial->hasComputed())->toBeTrue()
        ->and($financial->needsSubject())->toBeTrue()
        ->and($financial->strict)->toBeTrue()
        ->and($financial->auto)->toBeTrue()
        ->and($financial->ring)->toBe('default')
        ->and($financial->algorithms)->toBe(Algorithm::cases())
        ->and($financial->policy())->toBe(TamperedWritePolicy::Refuse)
        ->and($financial->usesFieldTags())->toBeTrue()
        ->and($seals->auto())->toHaveCount(2);
});

it('applies a reusable definition under the inline calls', function (): void {
    $identity = app(DefinitionRegistry::class)->for(Invoice::class)->get('identity');

    // PartyIdentitySeal says strict(); the inline lenient() wins.
    expect($identity->manifest())->toBe([['a:meta', 'json'], ['a:number', 'auto'], ['a:secret', 'plain']])
        ->and($identity->strict)->toBeFalse()
        ->and($identity->needsSubject())->toBeFalse()
        ->and($identity->readColumns())->toBe(['meta', 'number', 'secret']);
});

it('infers declared types from casts', function (?string $cast, ?string $tag): void {
    expect(Inference::fromCast($cast)?->tag())->toBe($tag);
})->with([
    [null, 'auto'], ['int', 'int'], ['timestamp', 'auto'], ['boolean', 'bool'], ['decimal:3', 'dec:3'], ['decimal:31', null],
    ['float', null], ['double', null], ['real', null], ['string', 'str'], ['hashed', 'str'], ['encrypted', 'str'], ['encrypted:array', 'str'],
    ['date', 'date'], ['immutable_date', 'date'], ['datetime', 'dt'], ['datetime:Y-m-d', 'dt'], ['immutable_datetime', 'dt'],
    ['array', 'json'], ['json', 'json'], ['object', 'json'], ['collection', 'json'],
    [InvoiceStatus::class, 'str'], [IntBacked::class, 'int'],
    ['Illuminate\Database\Eloquent\Casts\AsStringable', 'str'], ['Illuminate\Database\Eloquent\Casts\AsEncryptedCollection', 'str'],
    ['Illuminate\Database\Eloquent\Casts\AsArrayObject', 'json'], ['Illuminate\Database\Eloquent\Casts\AsCollection:App\Data', 'json'],
    ['App\Casts\Money', 'auto'],
]);

it('compiles every option of the builder', function (): void {
    archiveRing();
    $class = definedBy(static function (SealBuilder $seals): void {
        $seals->seal('all')
            ->attributes('number')
            ->string('currency')->integer('customer_id')->boolean('paid')->decimal('amount', 2)->float('ratio', 3)
            ->datetime('created_at')->date('due_on')->json('meta')->binary('note')->plaintext('secret')
            ->computed('total', static fn (Model $m): string => '1', SealType::decimal(2))
            ->ring('default')->acceptRings('archive')->algorithms(Algorithm::HmacSha256, Algorithm::HmacSha256)
            ->manual()->auto()->manual()->verifyOnRetrieve(Reaction::Report)->fieldTags(false)
            ->scope(static fn (Model $m): string => 'x')->onTamperedWrite(TamperedWritePolicy::Skip)->strict();
    });

    $seal = app(DefinitionRegistry::class)->for($class)->get('all');

    expect($seal->manifest())->toBe([
        ['a:amount', 'dec:2'], ['a:created_at', 'dt'], ['a:currency', 'str'], ['a:customer_id', 'int'], ['a:due_on', 'date'],
        ['a:meta', 'json'], ['a:note', 'bin'], ['a:number', 'auto'], ['a:paid', 'bool'], ['a:ratio', 'flt:3'], ['a:secret', 'plain'],
        ['c:total', 'dec:2'],
    ])
        ->and($seal->acceptRings)->toBe(['archive'])
        ->and($seal->acceptsRing('archive'))->toBeTrue()
        ->and($seal->algorithms)->toBe([Algorithm::HmacSha256])
        ->and($seal->auto)->toBeFalse()
        ->and($seal->verifiesOnRetrieve)->toBeTrue()
        ->and($seal->retrieveReaction)->toBe(Reaction::Report)
        ->and($seal->usesFieldTags())->toBeFalse()
        ->and($seal->policy())->toBe(TamperedWritePolicy::Skip)
        ->and($seal->field('c:total')?->isComputed())->toBeTrue()
        ->and($seal->field('a:nope'))->toBeNull()
        ->and(app(DefinitionRegistry::class)->for($class)->auto())->toBe([]);
});

it('lists every definition problem at once', function (): void {
    // Created in the test body, so they capture $this — exactly what the registry refuses.
    $captures = fn (): int => 1;
    $scope = fn (): string => 'x';

    $class = definedBy(static function (SealBuilder $seals) use ($captures, $scope): void {
        $seals->seal('Bad Name')->attributes('number');
        $seals->seal('dup')->attributes('number');
        $seals->seal('dup')->attributes('number');
        $seals->seal('empty');
        $seals->seal('broken')
            ->attributes('number', 'number', 'id', 'bad-column', 'ratio', 'big')
            ->computed('Bad', static fn (): int => 1)
            ->computed('twice', static fn (): int => 1)
            ->computed('twice', static fn (): int => 2)
            ->computed('captures', $captures)
            ->decimal('amount', 31)
            ->scope($scope)
            ->ring('default')->acceptRings('default', 'nowhere')
            ->algorithms(Algorithm::HmacSha256);
        $seals->seal('ringless')->attributes('number')->ring('nowhere');
        $seals->seal('noalgo')->attributes('number')->algorithms();
        $seals->seal('outside')->attributes('number')->ring('http')->algorithms(Algorithm::HmacSha512);
        $seals->seal('using')->attributes('number')->using(stdClass::class);
    });

    try {
        app(DefinitionRegistry::class)->for($class);
        $this->fail('expected InvalidSealDefinitionException');
    } catch (InvalidSealDefinitionException $exception) {
        $problems = implode("\n", $exception->problems());

        expect($problems)
            ->toContain('the seal name [Bad Name] is invalid')
            ->toContain('the seal [dup] is declared twice')
            ->toContain('seal [empty] has no fields')
            ->toContain('lists the field [a:number] twice')
            ->toContain('lists the primary key [id]')
            ->toContain('invalid column [bad-column]')
            ->toContain('field [a:ratio] is cast to a float')
            ->toContain('field [a:big] is cast to a float or an out-of-range decimal')
            ->toContain('invalid computed name [Bad]')
            ->toContain('declares the computed field [c:twice] twice')
            ->toContain('computed field [c:captures] must be a static closure')
            ->toContain('[a:amount] with scale 31')
            ->toContain('scope must be a static closure')
            ->toContain('lists its own ring [default]')
            ->toContain('accepts the unknown ring [nowhere]')
            ->toContain('uses the unknown ring [nowhere]')
            ->toContain('seal [noalgo] allows no algorithm')
            ->toContain('allows [hmac-sha512], which ring [http] does not')
            ->toContain('seal [outside] uses the ring [http], which HTTP message signatures use')
            ->toContain('uses [stdClass], which is not a SealDefinition');
    }
});

it('refuses a model that declares no seals', function (): void {
    expect(fn () => app(DefinitionRegistry::class)->for(definedBy(static function (): void {})))
        ->toThrow(InvalidSealDefinitionException::class, 'it declares no seals');
});

it('refuses models that are not sealable and seals that are not declared', function (): void {
    expect(fn () => app(DefinitionRegistry::class)->for(InvoiceLine::class))->toThrow(SealingMisconfiguredException::class, 'is not sealable')
        ->and(fn () => Sentinel::verify(new InvoiceLine))->toThrow(SealingMisconfiguredException::class)
        ->and(fn () => Sentinel::for(invoice(), 'nope'))->toThrow(SealingMisconfiguredException::class, 'declares no seal [nope]')
        ->and(fn () => Sentinel::model(Invoice::class)->definition('nope'))->toThrow(SealingMisconfiguredException::class)
        ->and(fn () => Sentinel::for(invoice(), "bad\nname"))->toThrow(SealingMisconfiguredException::class, '(invalid)');
});

it('exposes class-level seal information', function (): void {
    $sealed = invoice();
    config()->set('sentinel.sealing.allow_suspension', true);
    $unsealed = Sentinel::withoutSealing(fn () => invoice(), 'import');

    expect(Sentinel::model(Invoice::class)->seals())->toBe(['financial', 'identity'])
        ->and(Sentinel::model(Invoice::class)->definition('identity')->name)->toBe('identity')
        ->and(Sentinel::model(Invoice::class)->unsealedQuery()->pluck('id')->all())->toBe([$unsealed->id])
        ->and(Invoice::query()->whereSealed()->pluck('id')->all())->toBe([$sealed->id])
        ->and(Invoice::query()->whereNotSealed('identity')->pluck('id')->all())->toBe([$unsealed->id])
        ->and(Invoice::query()->withSeals()->find($sealed->id)?->relationLoaded('sentinelSeals'))->toBeTrue()
        ->and(PlainRecord::query()->whereSealed()->count())->toBe(0);
});
