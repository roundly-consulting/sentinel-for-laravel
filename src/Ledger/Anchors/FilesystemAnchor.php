<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Ledger\Anchors;

use Illuminate\Contracts\Filesystem\Filesystem;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Sentinel\Contracts\Anchor;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;
use RoundlyConsulting\Sentinel\Exceptions\AnchorPublishException;
use RoundlyConsulting\Sentinel\Ledger\AnchorCodec;

/**
 * Every checkpoint as `{path}/{connection}/{seq}.json` (written once) plus
 * `{path}/{connection}/latest.json` on a disk. Object storage with object lock or versioning
 * keeps them tamper-proof.
 *
 * @internal
 */
final readonly class FilesystemAnchor implements Anchor
{
    public function __construct(
        private Filesystem $disk,
        private string $path,
    ) {}

    public function name(): string
    {
        return 'filesystem';
    }

    public function publish(AnchorPayload $payload): void
    {
        $json = AnchorCodec::encode($payload);
        $directory = $this->directory($payload->connection);

        $numbered = "{$directory}/{$payload->seq}.json";

        // Write-once: a numbered file that holds another checkpoint is evidence, never replaced.
        if ($this->disk->exists($numbered)) {
            if ($this->disk->get($numbered) !== $json) {
                throw AnchorPublishException::diverged("anchor [filesystem] already holds another seq {$payload->seq}");
            }
        } else {
            $this->disk->put($numbered, $json);
        }

        $this->disk->put("{$directory}/latest.json", $json);
    }

    public function latest(string $connection): ?AnchorPayload
    {
        $file = $this->directory($connection).'/latest.json';

        if (! $this->disk->exists($file)) {
            return null;
        }

        return AnchorCodec::decode((string) $this->disk->get($file));
    }

    private function directory(string $connection): string
    {
        // A connection name is config, but it becomes a path: keep it one safe segment.
        $segment = preg_match('/^[A-Za-z0-9_.-]{1,64}$/D', $connection) === 1 && ! in_array($connection, ['.', '..'], true)
            ? $connection
            : 'conn-'.substr((new Digest)->hex($connection), 0, 32);

        return trim($this->path, '/').'/'.$segment;
    }
}
