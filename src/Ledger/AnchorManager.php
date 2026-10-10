<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Ledger;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Log\LogManager;
use RoundlyConsulting\Sentinel\Contracts\Anchor;
use RoundlyConsulting\Sentinel\Contracts\WriteOnlyAnchor;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPublication;
use RoundlyConsulting\Sentinel\Events\AnchorPublishFailed;
use RoundlyConsulting\Sentinel\Exceptions\AnchorPublishException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Ledger\Anchors\CacheAnchor;
use RoundlyConsulting\Sentinel\Ledger\Anchors\FilesystemAnchor;
use RoundlyConsulting\Sentinel\Ledger\Anchors\LogAnchor;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Support\Tables;
use Throwable;

/**
 * Resolves `sentinel.ledger.anchors` to anchors and publishes checkpoints to them. A
 * singleton holding only driver factories (code), so `Sentinel::fake()` keeps registered
 * extensions; the anchors themselves are built per use.
 *
 * Publication is best effort: a failing anchor fires `AnchorPublishFailed`, is logged, and
 * never rolls back a checkpoint.
 *
 * @internal
 */
final class AnchorManager
{
    /** @var array<string, Closure> */
    private array $drivers = [];

    public function __construct(private readonly Container $container) {}

    /**
     * Register a custom anchor driver: `fn (Container $app, array $config): Anchor`.
     */
    public function extend(string $driver, Closure $factory): void
    {
        $this->drivers[$driver] = $factory;
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return Settings::anchors();
    }

    /**
     * @return list<Anchor>
     */
    public function anchors(): array
    {
        return array_map($this->build(...), $this->names());
    }

    public function build(string $name): Anchor
    {
        $config = Settings::anchorDriver($name);

        $prefix = "ledger.anchor_drivers.{$name}";

        $anchor = match (true) {
            $name === 'cache' => new CacheAnchor(
                $this->container->make('cache')->store(Settings::optionalString("{$prefix}.store", $config['store'] ?? null)),
                self::required("{$prefix}.key", $config['key'] ?? null, 'sentinel:ledger:anchor'),
            ),
            $name === 'filesystem' => new FilesystemAnchor(
                $this->container->make('filesystem')->disk(Settings::optionalString("{$prefix}.disk", $config['disk'] ?? null)),
                self::required("{$prefix}.path", $config['path'] ?? null, 'sentinel/anchors'),
            ),
            $name === 'log' => new LogAnchor($this->container->make(LogManager::class)->channel(Settings::optionalString("{$prefix}.channel", $config['channel'] ?? null))),
            isset($this->drivers[$name]) => ($this->drivers[$name])($this->container, $config),
            default => throw InvalidSentinelConfigurationException::unknownAnchor($name),
        };

        return $anchor instanceof Anchor ? $anchor : throw InvalidSentinelConfigurationException::unknownAnchor($name);
    }

    /**
     * Publish a payload to every anchor — or, with `onlyLagging`, only to those that report
     * an older checkpoint (a failure of an earlier run).
     *
     * An anchor is never overwritten with a checkpoint that does not extend what it holds:
     * when the database lacks the anchored checkpoint (a restore) or holds it with another
     * root, the publication is refused and reported, so the evidence survives until someone
     * looks. An anchor that already holds this checkpoint or a newer one of the same chain
     * (a concurrent run) counts as published.
     *
     * @return list<AnchorPublication>
     */
    public function publish(AnchorPayload $payload, bool $onlyLagging = false): array
    {
        $publications = [];

        foreach ($this->names() as $name) {
            try {
                $anchor = $this->build($name);
                $latest = $anchor->latest($payload->connection);

                if ($latest !== null) {
                    $this->guard($name, $latest, $payload);
                }

                // Nothing held is lagging too (a failed first publication, a flushed cache); only
                // a write-only anchor, which never holds anything, is not re-sent every run.
                if ($onlyLagging && ($latest === null ? $anchor instanceof WriteOnlyAnchor : $latest->seq >= $payload->seq)) {
                    continue;
                }

                if ($latest === null || $latest->seq < $payload->seq) {
                    $anchor->publish($payload);
                }

                $publications[] = new AnchorPublication($name, true);
            } catch (InvalidSentinelConfigurationException $exception) {
                throw $exception;
            } catch (Throwable $exception) {
                $error = $exception::class.': '.mb_strimwidth($exception->getMessage(), 0, 300, '…');

                $this->container->make(Dispatcher::class)->dispatch(new AnchorPublishFailed($name, $payload->connection, $payload->seq, $error));
                $this->container->make(LogManager::class)->channel(Settings::logChannel())->warning('Sentinel: an anchor did not accept the newest checkpoint.', [
                    'anchor' => $name,
                    'connection' => $payload->connection,
                    'seq' => $payload->seq,
                    'error' => $error,
                ]);

                $publications[] = new AnchorPublication($name, false, $error);
            }
        }

        return $publications;
    }

    /**
     * Refuse to replace what an anchor holds unless the database still has that checkpoint,
     * with the same root.
     */
    private function guard(string $name, AnchorPayload $held, AnchorPayload $payload): void
    {
        $local = Tables::checkpoints($payload->connection)->where('seq', $held->seq)->first();

        if ($local === null) {
            $tail = (int) Tables::checkpoints($payload->connection)->max('seq');

            throw AnchorPublishException::diverged("anchor [{$name}] holds seq {$held->seq}, the database {$tail}");
        }

        if ((string) $local->getRawOriginal('root') !== $held->root) {
            throw AnchorPublishException::diverged("anchor [{$name}] holds seq {$held->seq} with another root than the database");
        }
    }

    /**
     * A required anchor setting: the default when not set (absent, null or blank — an empty
     * env value); a non-string throws rather than silently anchoring under the default key
     * or path.
     */
    private static function required(string $key, mixed $value, string $default): string
    {
        $value = Settings::nullIfBlank($value) ?? $default;

        if (! is_string($value)) {
            throw InvalidSentinelConfigurationException::invalidValue($key, 'must be a string');
        }

        return $value;
    }
}
