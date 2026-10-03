<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency;

use JsonException;
use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * A stored response for replay: status, the allow-listed headers (never `Set-Cookie`) and the
 * body (base64 when not UTF-8). Streamed, file and oversized responses are not replayable —
 * their keys answer 409 instead.
 */
final readonly class ResponseSnapshot
{
    /**
     * @param  array<string, list<string>>  $headers  lowercase name → values
     */
    public function __construct(
        public int $status,
        public array $headers,
        public string $body,
        public bool $replayable = true,
    ) {}

    /**
     * @param  list<string>  $replayedHeaders
     */
    public static function fromResponse(Response $response, array $replayedHeaders, int $maxBytes): self
    {
        $content = $response->getContent();

        if ($response instanceof StreamedResponse || $response instanceof BinaryFileResponse || $content === false || strlen($content) > $maxBytes) {
            return new self($response->getStatusCode(), [], '', false);
        }

        $headers = [];

        foreach ($response->headers->all() as $name => $values) {
            $name = strtolower((string) $name);

            if ($name !== 'set-cookie' && in_array($name, $replayedHeaders, true)) {
                $headers[$name] = array_values(array_map(strval(...), array_filter($values, static fn (mixed $value): bool => $value !== null)));
            }
        }

        return new self($response->getStatusCode(), $headers, $content);
    }

    /**
     * The result of a programmatic idempotent call.
     *
     * @throws JsonException when the value is not JSON-encodable
     */
    public static function forValue(mixed $value): self
    {
        return new self(200, [], json_encode($value, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    /**
     * A completed call whose result could not be stored: its key answers 409 unavailable.
     */
    public static function unreplayable(int $status = 200): self
    {
        return new self($status, [], '', false);
    }

    public function value(): mixed
    {
        try {
            return json_decode($this->body, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw CorruptRecordException::idempotency('the stored result is not JSON');
        }
    }

    public function toResponse(string $replayHeader): Response
    {
        $response = new Response($this->body, $this->status, $this->headers);
        $response->headers->set($replayHeader, 'true');

        return $response;
    }

    public function toJson(): string
    {
        $utf8 = mb_check_encoding($this->body, 'UTF-8');
        // A header value may be raw bytes (a binary ETag, a redirect to a user's path): store
        // every value base64 then, so storing never fails after the handler ran.
        $textHeaders = array_all($this->headers, static fn (array $values): bool => array_all($values, static fn (string $value): bool => mb_check_encoding($value, 'UTF-8')));

        return json_encode([
            'v' => 1,
            'status' => $this->status,
            'headers' => $textHeaders ? $this->headers : array_map(static fn (array $values): array => array_map(Base64::encode(...), $values), $this->headers),
            'header_encoding' => $textHeaders ? 'utf8' : 'base64',
            'encoding' => $utf8 ? 'utf8' : 'base64',
            'body' => $utf8 ? $this->body : Base64::encode($this->body),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * @throws CorruptRecordException
     */
    public static function fromJson(string $json): self
    {
        try {
            $data = json_decode($json, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw CorruptRecordException::idempotency('the stored response is not JSON');
        }

        if (! is_array($data) || ($data['v'] ?? null) !== 1 || ! is_int($data['status'] ?? null) || ! is_array($data['headers'] ?? null) || ! is_string($data['body'] ?? null)) {
            throw CorruptRecordException::idempotency('the stored response is malformed');
        }

        $headers = [];
        $base64Headers = ($data['header_encoding'] ?? 'utf8') === 'base64';

        try {
            foreach ($data['headers'] as $name => $values) {
                if (! is_array($values)) {
                    throw CorruptRecordException::idempotency('the stored response is malformed');
                }

                $values = array_values(array_map(strval(...), array_filter($values, is_scalar(...))));
                $headers[(string) $name] = $base64Headers ? array_map(Base64::decode(...), $values) : $values;
            }

            $body = ($data['encoding'] ?? 'utf8') === 'base64' ? Base64::decode($data['body']) : $data['body'];
        } catch (InvalidEncodingException) {
            throw CorruptRecordException::idempotency('the stored response is malformed');
        }

        return new self($data['status'], $headers, $body);
    }
}
