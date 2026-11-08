<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Accessors\KeyRingHandle;
use RoundlyConsulting\Sentinel\Accessors\MacsAccessor;
use RoundlyConsulting\Sentinel\Actions\Macs\SignWithSecretAction;
use RoundlyConsulting\Sentinel\Actions\Macs\VerifyWithSecretsAction;
use RoundlyConsulting\Sentinel\DataTransferObjects\ImportKeyRequest;
use RoundlyConsulting\Sentinel\Keys\ImportedMaterial;
use RoundlyConsulting\Sentinel\Keys\SecretMacRules;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Testing\SentinelFake;
use RoundlyConsulting\Sentinel\Tests\Support\SourceScan;

/**
 * §10 item 33: every parameter that can carry key material, a nonce or a raw secret value is
 * `#[\SensitiveParameter]`, so it is redacted from stack traces and logs.
 */
it('marks every material-bearing parameter in Keys and Accessors as sensitive', function (): void {
    $names = ['material', 'secret', 'privateKey', 'key', 'keyMaterial', 'nonce', 'value', 'ikm', 'bytes', 'encoded', 'private', 'entry', 'entries'];
    $checked = 0;
    $offenders = [];

    foreach (array_keys(SourceScan::classes()) as $class) {
        if (! preg_match('/^RoundlyConsulting\\\\Sentinel\\\\(Keys|Accessors)\\\\/', $class) || ! class_exists($class) || enum_exists($class)) {
            continue;
        }

        foreach ((new ReflectionClass($class))->getMethods() as $method) {
            if ($method->getDeclaringClass()->getName() !== $class) {
                continue;
            }

            foreach ($method->getParameters() as $parameter) {
                if (! in_array($parameter->getName(), $names, true)) {
                    continue;
                }

                $checked++;

                if ($parameter->getAttributes(SensitiveParameter::class) === []) {
                    $offenders[] = "{$class}::{$method->getName()}(\${$parameter->getName()})";
                }
            }
        }
    }

    expect($checked)->toBeGreaterThan(10)->and($offenders)->toBe([]);
});

it('marks imported key material as sensitive on every path into the import', function (string $class, string $method): void {
    $parameter = array_values(array_filter(
        (new ReflectionMethod($class, $method))->getParameters(),
        static fn (ReflectionParameter $parameter): bool => $parameter->getName() === 'material',
    ));

    expect($parameter)->toHaveCount(1)
        ->and($parameter[0]->getAttributes(SensitiveParameter::class))->toHaveCount(1);
})->with([
    [ImportKeyRequest::class, '__construct'],
    [KeyRingHandle::class, 'import'],
    [ImportedMaterial::class, 'parse'],
]);

it('marks the secrets and the MAC of Sentinel::macs() as sensitive on every layer', function (string $class, string $method, array $sensitive): void {
    $marked = array_values(array_map(
        static fn (ReflectionParameter $parameter): string => $parameter->getName(),
        array_filter(
            (new ReflectionMethod($class, $method))->getParameters(),
            static fn (ReflectionParameter $parameter): bool => $parameter->getAttributes(SensitiveParameter::class) !== [],
        ),
    ));

    expect($marked)->toBe($sensitive);
})->with([
    [SentinelManager::class, 'signWithSecret', ['secret']],
    [SentinelManager::class, 'verifyWithSecrets', ['mac', 'secrets']],
    [SentinelFake::class, 'signWithSecret', ['secret']],
    [SentinelFake::class, 'verifyWithSecrets', ['mac', 'secrets']],
    [MacsAccessor::class, 'sign', ['secret']],
    [MacsAccessor::class, 'verify', ['mac', 'secrets']],
    [SignWithSecretAction::class, 'execute', ['secret']],
    [VerifyWithSecretsAction::class, 'execute', ['mac', 'secrets']],
    [Signers::class, 'macWithSecret', ['secret']],
    [SecretMacRules::class, 'secret', ['secret']],
    [SecretMacRules::class, 'secrets', ['secrets']],
]);
