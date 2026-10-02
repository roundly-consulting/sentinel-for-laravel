<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Support;

use PhpToken;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Token-level scans of `src/` for the bespoke arch pins (plan §12.1). Tokens, not regexes:
 * a docblock that mentions `hash_hkdf(` is a comment token and never counts as a call.
 */
final class SourceScan
{
    public const string ROOT_NAMESPACE = 'RoundlyConsulting\\Sentinel\\';

    /**
     * @return array<string, string> class FQCN => file, for every PHP file under src/
     */
    public static function classes(): array
    {
        $src = realpath(__DIR__.'/../../src');
        $classes = [];

        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator((string) $src));

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $relative = substr((string) $file->getRealPath(), strlen((string) $src) + 1, -4);
                $classes[self::ROOT_NAMESPACE.str_replace('/', '\\', $relative)] = (string) $file->getRealPath();
            }
        }

        ksort($classes);

        return $classes;
    }

    /**
     * Calls of a global function (`name(` or `\name(`), excluding method/static calls and
     * declarations.
     */
    public static function functionCalls(string $file, string $function): int
    {
        $tokens = self::meaningful($file);
        $count = 0;

        foreach ($tokens as $i => $token) {
            $name = ltrim($token->text, '\\');

            if (! $token->is([T_STRING, T_NAME_FULLY_QUALIFIED]) || strcasecmp($name, $function) !== 0) {
                continue;
            }

            $next = $tokens[$i + 1] ?? null;
            $previous = $tokens[$i - 1] ?? null;

            if ($next?->text !== '(' || ($previous !== null && $previous->is([T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW, T_CONST]))) {
                continue;
            }

            $count++;
        }

        return $count;
    }

    /**
     * Static calls `Class::method(` where Class's short or imported name matches.
     *
     * @param  list<string>  $classes  short names (`Date`, `Carbon`)
     */
    public static function staticCalls(string $file, array $classes, string $method): int
    {
        $tokens = self::meaningful($file);
        $count = 0;

        foreach ($tokens as $i => $token) {
            if (! $token->is(T_DOUBLE_COLON)) {
                continue;
            }

            $class = $tokens[$i - 1] ?? null;
            $name = $tokens[$i + 1] ?? null;

            if ($class === null || $name === null || strcasecmp($name->text, $method) !== 0) {
                continue;
            }

            $short = substr((string) strrchr('\\'.$class->text, '\\'), 1);

            if (in_array($short, $classes, true)) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * The top-level `use` imports of a file (class imports only).
     *
     * @return list<string>
     */
    public static function imports(string $file): array
    {
        $tokens = self::meaningful($file);
        $imports = [];
        $depth = 0;

        foreach ($tokens as $i => $token) {
            if ($token->text === '{') {
                $depth++;
            } elseif ($token->text === '}') {
                $depth--;
            }

            if ($depth !== 0 || ! $token->is(T_USE)) {
                continue;
            }

            $next = $tokens[$i + 1] ?? null;

            if ($next !== null && $next->is([T_NAME_QUALIFIED, T_STRING, T_NAME_FULLY_QUALIFIED])) {
                $imports[] = ltrim($next->text, '\\');
            }
        }

        return $imports;
    }

    /**
     * The argument tokens of every call to `$function(`, as concatenated text.
     *
     * @return list<string>
     */
    public static function callArguments(string $file, string $function): array
    {
        $tokens = self::meaningful($file);
        $calls = [];

        foreach ($tokens as $i => $token) {
            if (! $token->is([T_STRING, T_NAME_FULLY_QUALIFIED]) || ltrim($token->text, '\\') !== $function || ($tokens[$i + 1] ?? null)?->text !== '(') {
                continue;
            }

            $depth = 0;
            $text = '';

            for ($j = $i + 1; $j < count($tokens); $j++) {
                $depth += match ($tokens[$j]->text) {
                    '(' => 1,
                    ')' => -1,
                    default => 0,
                };

                $text .= $tokens[$j]->text.' ';

                if ($depth === 0) {
                    break;
                }
            }

            $calls[] = $text;
        }

        return $calls;
    }

    /**
     * @return list<PhpToken>
     */
    private static function meaningful(string $file): array
    {
        return array_values(array_filter(
            PhpToken::tokenize((string) file_get_contents($file)),
            static fn (PhpToken $token): bool => ! $token->isIgnorable(),
        ));
    }
}
