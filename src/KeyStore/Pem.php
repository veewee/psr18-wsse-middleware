<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore;

use Phpro\ResourceStream\Factory\TmpStream;
use Phpro\ResourceStream\ResourceStream;

/**
 * One or more certificates concatenated into a single PEM bundle, the form a trusted-CA or intermediates file
 * carries. Holds public certificate text only, never key material.
 */
final readonly class Pem
{
    private function __construct(
        private string $value,
    ) {
    }

    public static function fromCertificates(Certificate ...$certificates): self
    {
        return new self(implode("\n", array_map(
            static fn (Certificate $certificate): string => $certificate->contents(),
            $certificates,
        )));
    }

    public function toString(): string
    {
        return $this->value;
    }

    /**
     * Writes the bundle to a temporary file and returns the live stream. Callers that need a filesystem path
     * (openssl's path-based APIs) read its uri(); the temp file is removed when the returned stream goes out
     * of scope, so no manual cleanup is needed.
     *
     * @return ResourceStream<resource>
     */
    public function toResource(): ResourceStream
    {
        $stream = TmpStream::create();
        $stream->write($this->value);
        // openssl opens the path with a separate descriptor and would otherwise read an empty file.
        fflush($stream->unwrap());

        return $stream;
    }
}
