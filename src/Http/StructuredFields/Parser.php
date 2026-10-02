<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\StructuredFields;

use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Sentinel\Exceptions\StructuredFieldException;

/**
 * RFC 9651 §4.2 structured field parsing — Lists, Dictionaries and Items with every bare
 * type (Integer, Decimal, String, Token, Byte Sequence, Boolean, Date, Display String).
 * Strict: any deviation fails the whole field. Several field lines are combined with
 * `, ` first (RFC 9110 §5.3).
 *
 * @internal
 *
 * @phpstan-import-type BareItem from Parameters
 */
final class Parser
{
    private int $position = 0;

    private function __construct(private readonly string $input) {}

    /**
     * @param  string|list<string>  $field
     * @return list<Item|InnerList>
     */
    public static function list(string|array $field): array
    {
        $parser = self::for($field);
        $members = [];

        while (! $parser->done()) {
            $members[] = $parser->itemOrInnerList();
            $parser->separator();
        }

        return $members;
    }

    /**
     * @param  string|list<string>  $field
     * @return array<string, Item|InnerList>
     */
    public static function dictionary(string|array $field): array
    {
        $parser = self::for($field);
        $members = [];

        while (! $parser->done()) {
            $key = $parser->key();

            if ($parser->peek() === '=') {
                $parser->position++;
                $members[$key] = $parser->itemOrInnerList();
            } else {
                $members[$key] = new Item(true, $parser->parameters());
            }

            $parser->separator();
        }

        return $members;
    }

    /**
     * @param  string|list<string>  $field
     */
    public static function item(string|array $field): Item
    {
        $parser = self::for($field);
        $item = $parser->parseItem();

        if (! $parser->done()) {
            $parser->fail('trailing characters');
        }

        return $item;
    }

    /**
     * @param  string|list<string>  $field
     */
    private static function for(string|array $field): self
    {
        $input = is_array($field) ? implode(', ', $field) : $field;

        if (preg_match('/[^\x00-\x7F]/', $input, $match, PREG_OFFSET_CAPTURE) === 1) {
            throw StructuredFieldException::parse('a non-ASCII character', $match[0][1]);
        }

        $parser = new self($input);
        $parser->skip(' ');

        return $parser;
    }

    private function done(): bool
    {
        $this->skip(' ');

        return $this->position >= strlen($this->input);
    }

    /**
     * Between members: optional whitespace, a comma, optional whitespace, then another member.
     */
    private function separator(): void
    {
        $this->skip(" \t");

        if ($this->position >= strlen($this->input)) {
            return;
        }

        if ($this->peek() !== ',') {
            $this->fail('a missing comma');
        }

        $this->position++;
        $this->skip(" \t");

        if ($this->position >= strlen($this->input)) {
            $this->fail('a trailing comma');
        }
    }

    private function itemOrInnerList(): Item|InnerList
    {
        return $this->peek() === '(' ? $this->innerList() : $this->parseItem();
    }

    private function innerList(): InnerList
    {
        $this->position++;
        $items = [];

        while ($this->position < strlen($this->input)) {
            $this->skip(' ');

            if ($this->peek() === ')') {
                $this->position++;

                return new InnerList($items, $this->parameters());
            }

            $items[] = $this->parseItem();
            $next = $this->peek();

            if ($next !== ' ' && $next !== ')') {
                $this->fail('an inner list member without a separator');
            }
        }

        $this->fail('an unterminated inner list');
    }

    private function parseItem(): Item
    {
        return new Item($this->bareItem(), $this->parameters());
    }

    /**
     * @return BareItem
     */
    private function bareItem(): int|float|string|bool|Token|ByteSequence|Date|DisplayString
    {
        $char = $this->peek();

        return match (true) {
            $char === '-' || ctype_digit($char) => $this->number(),
            $char === '"' => $this->string(),
            $char === '*' || ctype_alpha($char) => $this->token(),
            $char === ':' => $this->byteSequence(),
            $char === '?' => $this->boolean(),
            $char === '@' => $this->date(),
            $char === '%' => $this->displayString(),
            default => $this->fail('an unknown item type'),
        };
    }

    private function parameters(): Parameters
    {
        $values = [];

        while ($this->peek() === ';') {
            $this->position++;
            $this->skip(' ');
            $key = $this->key();
            $value = true;

            if ($this->peek() === '=') {
                $this->position++;
                $value = $this->bareItem();
            }

            $values[$key] = $value;
        }

        return new Parameters($values);
    }

    private function key(): string
    {
        $char = $this->peek();

        if ($char !== '*' && ! ($char >= 'a' && $char <= 'z')) {
            $this->fail('a key that does not start with a lowercase letter or *');
        }

        $length = strspn($this->input, 'abcdefghijklmnopqrstuvwxyz0123456789_-.*', $this->position);
        $key = substr($this->input, $this->position, $length);
        $this->position += $length;

        return $key;
    }

    private function number(): int|float
    {
        $start = $this->position;
        $negative = $this->peek() === '-';

        if ($negative) {
            $this->position++;
        }

        if (! ctype_digit($this->peek())) {
            $this->fail('a number without digits');
        }

        $integer = strspn($this->input, '0123456789', $this->position);
        $this->position += $integer;

        if ($this->peek() !== '.') {
            if ($integer > 15) {
                $this->fail('an integer of more than 15 digits');
            }

            $value = (int) substr($this->input, $start + ($negative ? 1 : 0), $integer);

            return $negative ? -$value : $value;
        }

        if ($integer > 12) {
            $this->fail('a decimal of more than 12 integer digits');
        }

        $this->position++;
        $fraction = strspn($this->input, '0123456789', $this->position);

        if ($fraction === 0 || $fraction > 3) {
            $this->fail('a decimal without 1 to 3 fractional digits');
        }

        $this->position += $fraction;

        return (float) substr($this->input, $start, $this->position - $start);
    }

    private function string(): string
    {
        $this->position++;
        $value = '';

        while ($this->position < strlen($this->input)) {
            $char = $this->input[$this->position++];

            if ($char === '\\') {
                $next = $this->input[$this->position] ?? '';

                if ($next !== '"' && $next !== '\\') {
                    $this->fail('an invalid string escape');
                }

                $value .= $next;
                $this->position++;
            } elseif ($char === '"') {
                return $value;
            } elseif (ord($char) < 0x20 || ord($char) > 0x7E) {
                $this->fail('a control character in a string');
            } else {
                $value .= $char;
            }
        }

        $this->fail('an unterminated string');
    }

    private function token(): Token
    {
        $length = strspn($this->input, "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz:/", $this->position);
        $token = substr($this->input, $this->position, $length);
        $this->position += $length;

        return new Token($token);
    }

    private function byteSequence(): ByteSequence
    {
        $this->position++;
        $end = strpos($this->input, ':', $this->position);

        if ($end === false) {
            $this->fail('an unterminated byte sequence');
        }

        $content = substr($this->input, $this->position, $end - $this->position);
        $this->position = $end + 1;

        if (preg_match('#^[A-Za-z0-9+/]*={0,2}$#D', $content) !== 1) {
            $this->fail('a byte sequence that is not base64');
        }

        if ($content === '') {
            return new ByteSequence('');
        }

        // Padding is synthesized when missing (RFC 9651 §4.2.7 recipient behavior).
        $padded = rtrim($content, '=');
        $padded .= str_repeat('=', (4 - strlen($padded) % 4) % 4);

        try {
            return new ByteSequence(Base64::decode($padded));
        } catch (InvalidEncodingException) {
            $this->fail('a byte sequence that is not base64');
        }
    }

    private function boolean(): bool
    {
        $this->position++;
        $char = $this->input[$this->position++] ?? '';

        return match ($char) {
            '1' => true,
            '0' => false,
            default => $this->fail('an invalid boolean'),
        };
    }

    private function date(): Date
    {
        $this->position++;
        $value = $this->number();

        return is_int($value) ? new Date($value) : $this->fail('a date that is not an integer');
    }

    private function displayString(): DisplayString
    {
        $this->position++;

        if ($this->peek() !== '"') {
            $this->fail('a display string without its opening quote');
        }

        $this->position++;
        $bytes = '';

        while ($this->position < strlen($this->input)) {
            $char = $this->input[$this->position++];

            if ($char === '%') {
                $hex = substr($this->input, $this->position, 2);

                if (preg_match('/^[0-9a-f]{2}$/D', $hex) !== 1) {
                    $this->fail('an invalid percent-encoding in a display string');
                }

                $bytes .= chr((int) hexdec($hex));
                $this->position += 2;
            } elseif ($char === '"') {
                return mb_check_encoding($bytes, 'UTF-8') ? new DisplayString($bytes) : $this->fail('a display string that is not UTF-8');
            } elseif (ord($char) < 0x20 || ord($char) > 0x7E) {
                $this->fail('a control character in a display string');
            } else {
                $bytes .= $char;
            }
        }

        $this->fail('an unterminated display string');
    }

    private function peek(): string
    {
        return $this->input[$this->position] ?? '';
    }

    private function skip(string $characters): void
    {
        $this->position += strspn($this->input, $characters, $this->position);
    }

    private function fail(string $what): never
    {
        throw StructuredFieldException::parse($what, $this->position);
    }
}
