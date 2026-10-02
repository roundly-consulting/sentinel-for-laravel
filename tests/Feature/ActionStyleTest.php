<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Response as PsrResponse;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\Actions\Seals\SealModelAction;
use RoundlyConsulting\Sentinel\Actions\Seals\VerifyModelAction;
use RoundlyConsulting\Sentinel\Actions\Seals\VerifyModelsAction;
use RoundlyConsulting\Sentinel\Actions\Signatures\VerifyRequestSignatureAction;
use RoundlyConsulting\Sentinel\Actions\Signatures\VerifyResponseSignatureAction;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifyManyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifyRequest;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;

/**
 * I-6: the third calling style — the raw action — takes only public inputs: request DTOs with
 * an optional seal (null = the default seal) and signature profiles by name.
 */
it('seals through the action with the default or a named seal', function (): void {
    $invoice = invoice();

    $default = app(SealModelAction::class)->execute(new SealRequest($invoice, reason: 'INC-1'));
    $named = app(SealModelAction::class)->execute(new SealRequest($invoice, 'identity'));

    expect($default->seal)->toBe('financial')
        ->and($default->version)->toBe(2)
        ->and($default->event)->toBe(SealEvent::Resealed)
        ->and($named->seal)->toBe('identity')
        ->and(Sentinel::for($invoice)->history()[0]->reason)->toBe('INC-1');
});

it('verifies one model and many models through the actions', function (): void {
    $invoice = invoice();
    $other = invoice();
    DB::table('invoices')->where('id', $other->id)->update(['amount' => '0.01']);

    $default = app(VerifyModelAction::class)->execute(new VerifyRequest($invoice));
    $named = app(VerifyModelAction::class)->execute(new VerifyRequest($other, 'financial'));
    $every = app(VerifyModelsAction::class)->execute(new VerifyManyRequest([$invoice, $other]));
    $one = app(VerifyModelsAction::class)->execute(new VerifyManyRequest([$invoice, $other], 'identity'));

    expect($default->seal)->toBe('financial')
        ->and($default->status)->toBe(VerificationStatus::Intact)
        ->and($named->status)->toBe(VerificationStatus::Tampered)
        ->and($every->results)->toHaveCount(4)
        ->and($every->count(VerificationStatus::Tampered))->toBe(1)
        ->and($one->allIntact())->toBeTrue();
});

it('verifies request and response signatures through the actions by profile name', function (): void {
    partnerRing();

    $default = app(VerifyRequestSignatureAction::class)->execute(received(signedPartnerRequest()));
    $named = app(VerifyRequestSignatureAction::class)->execute(received(signedPartnerRequest()), 'default');

    expect($default->keyId)->toBe('partner')
        ->and($named->keyId)->toBe('partner')
        ->and(fn () => app(VerifyResponseSignatureAction::class)->execute(new PsrResponse(200), 'default'))
        ->toThrow(fn (HttpSignatureException $exception) => expect($exception->reason())->toBe(SignatureRejection::Missing));
});

it('throws exactly what the facade throws for an unknown seal or profile', function (Closure $action, Closure $facade): void {
    partnerRing();
    $invoice = invoice();
    $caught = static function (Closure $call) use ($invoice): array {
        try {
            $call($invoice);
        } catch (Throwable $exception) {
            return [$exception::class, $exception->getMessage()];
        }

        return ['nothing thrown'];
    };

    expect($caught($action))->toBe($caught($facade))
        ->and($caught($action)[0])->toBeIn([SealingMisconfiguredException::class, InvalidSentinelConfigurationException::class]);
})->with([
    'seal' => [
        static fn ($invoice) => app(SealModelAction::class)->execute(new SealRequest($invoice, 'nope')),
        static fn ($invoice) => Sentinel::seal($invoice, 'nope'),
    ],
    'verify' => [
        static fn ($invoice) => app(VerifyModelAction::class)->execute(new VerifyRequest($invoice, 'nope')),
        static fn ($invoice) => Sentinel::verify($invoice, 'nope'),
    ],
    'verify many' => [
        static fn ($invoice) => app(VerifyModelsAction::class)->execute(new VerifyManyRequest([$invoice], 'nope')),
        static fn ($invoice) => Sentinel::verifyMany([$invoice], 'nope'),
    ],
    'request profile' => [
        static fn () => app(VerifyRequestSignatureAction::class)->execute(received(signedPartnerRequest()), 'nope'),
        static fn () => Sentinel::signatures()->verify(received(signedPartnerRequest()), 'nope'),
    ],
    'response profile' => [
        static fn () => app(VerifyResponseSignatureAction::class)->execute(new PsrResponse(200), 'nope'),
        static fn () => Sentinel::signatures()->verifyResponse(new PsrResponse(200), 'nope'),
    ],
]);
