<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * A value could not be brought into canonical form. Canonicalization rejects rather than
 * guesses; the message names the field and the reason, never the value (it may be personal
 * data).
 */
final class CanonicalizationException extends SentinelException
{
    private function __construct(
        string $message,
        private readonly string $reason,
        private readonly ?string $field,
    ) {
        parent::__construct($message);
    }

    public static function invalidUtf8(?string $field = null): self
    {
        return self::make('invalid_utf8', $field, 'is not valid UTF-8; declare it binary()');
    }

    public static function notInteger(?string $field = null): self
    {
        return self::make('not_integer', $field, 'is not an integer');
    }

    public static function notRepresentable(?string $field = null): self
    {
        return self::make('not_representable', $field, 'is not representable at the declared scale');
    }

    public static function notBoolean(?string $field = null): self
    {
        return self::make('not_boolean', $field, 'is not a boolean');
    }

    public static function invalidDatetime(?string $field = null): self
    {
        return self::make('invalid_datetime', $field, 'is not a datetime');
    }

    public static function invalidDate(?string $field = null): self
    {
        return self::make('invalid_date', $field, 'is not a date');
    }

    public static function invalidJson(?string $field = null): self
    {
        return self::make('invalid_json', $field, 'is not JSON (or nests deeper than 64 levels)');
    }

    public static function floatRequiresDeclaration(?string $field = null): self
    {
        return self::make('float_requires_declaration', $field, 'is a float; declare float(column, scale) or decimal(column, scale)');
    }

    public static function computedModel(?string $field = null): self
    {
        return self::make('computed_model', $field, 'returned a Model; return its key or an array explicitly');
    }

    public static function undecryptable(?string $field = null): self
    {
        return self::make('undecryptable', $field, 'could not be decrypted through the model cast');
    }

    public static function unsupportedType(string $type, ?string $field = null): self
    {
        return self::make('unsupported_type', $field, "has an unsupported type [{$type}]");
    }

    /**
     * The machine-readable reason code (`invalid_utf8`, `not_integer`, …).
     */
    public function reason(): string
    {
        return $this->reason;
    }

    public function field(): ?string
    {
        return $this->field;
    }

    /**
     * The same failure, attributed to a field (values are canonicalized before their field
     * name is known when nested inside JSON).
     */
    public function forField(string $field): self
    {
        return $this->field === $field
            ? $this
            : new self(self::message($field, $this->reason), $this->reason, $field);
    }

    private static function make(string $reason, ?string $field, string $problem): self
    {
        return new self(self::message($field, $reason, $problem), $reason, $field);
    }

    private static function message(?string $field, string $reason, ?string $problem = null): string
    {
        $subject = $field === null ? 'The value' : "Field [{$field}]";

        return $problem === null
            ? "{$subject} could not be canonicalized (reason: {$reason})."
            : "{$subject} {$problem} (reason: {$reason}).";
    }
}
