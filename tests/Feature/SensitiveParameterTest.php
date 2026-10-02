<?php

declare(strict_types=1);

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
