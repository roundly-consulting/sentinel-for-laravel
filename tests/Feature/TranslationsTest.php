<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Enums\VerificationStatus;

/**
 * Every language ships the same keys (plan §5.17); every status has a label.
 */
it('ships the same translation keys in every language', function (string $file): void {
    $english = require __DIR__."/../../resources/lang/en/{$file}.php";
    $slovak = require __DIR__."/../../resources/lang/sk/{$file}.php";

    expect(array_keys($slovak))->toBe(array_keys($english))
        ->and($english)->not->toBeEmpty();
})->with(['messages', 'validation', 'statuses']);

it('labels every verification status', function (): void {
    $statuses = require __DIR__.'/../../resources/lang/en/statuses.php';

    expect(array_keys($statuses))->toBe(VerificationStatus::values()->all())
        ->and(trans('sentinel::statuses.tampered'))->toBe('Tampered');
});
