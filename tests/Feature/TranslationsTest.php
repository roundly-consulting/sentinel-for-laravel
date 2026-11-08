<?php

declare(strict_types=1);

use Illuminate\Support\Arr;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;

/**
 * Every language ships the same keys (plan §5.17); every status has a label.
 */
it('ships the same translation keys in every language', function (string $file): void {
    $english = require __DIR__."/../../resources/lang/en/{$file}.php";
    $slovak = require __DIR__."/../../resources/lang/sk/{$file}.php";

    $placeholders = static fn (array $lines): array => array_map(
        static function (string $line): array {
            preg_match_all('/:[a-z_]+/', $line, $found);
            $found = array_unique($found[0]);
            sort($found);

            return $found;
        },
        Arr::dot($lines),
    );

    expect(array_keys(Arr::dot($slovak)))->toBe(array_keys(Arr::dot($english)))
        ->and($placeholders($slovak))->toBe($placeholders($english))
        ->and($english)->not->toBeEmpty();
})->with(['messages', 'validation', 'statuses']);

it('translates the Sentinel::macs() refusals into Slovak', function (): void {
    app()->setLocale('sk');

    expect(AlgorithmNotAllowedException::notHmacForMacs(Algorithm::Ed25519)->getMessage())->toBe('Algoritmus [ed25519] nevytvára MAC; použite hmac-sha256, hmac-sha384 alebo hmac-sha512.')
        ->and(InvalidKeyMaterialException::emptySecret()->getMessage())->toBe('Tajný kľúč pre MAC nesmie byť prázdny.')
        ->and(InvalidKeyMaterialException::noSecrets()->getMessage())->toBe('Overenie MAC vyžaduje aspoň jeden tajný kľúč.')
        ->and(InvalidKeyMaterialException::tooManySecrets(8)->getMessage())->toBe('MAC sa overuje najviac voči 8 tajným kľúčom.');

    app()->setLocale('en');

    expect(InvalidKeyMaterialException::tooManySecrets(8)->getMessage())->toBe('A MAC is verified against at most 8 secrets.');
});

it('labels every verification status', function (): void {
    $statuses = require __DIR__.'/../../resources/lang/en/statuses.php';

    expect(array_keys($statuses))->toBe(VerificationStatus::values()->all())
        ->and(trans('sentinel::statuses.tampered'))->toBe('Tampered');
});
