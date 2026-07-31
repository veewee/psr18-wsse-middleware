<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore;

use Phpro\ResourceStream\Factory\TmpStream;
use Phpro\ResourceStream\ResourceStream;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidPemBundle;
use function Psl\File\read;

/**
 * One or more certificates concatenated into a single PEM bundle, the form a trusted-CA or intermediates file
 * carries. Holds public certificate text only, never key material.
 */
final readonly class Pem
{
    private const CERTIFICATE_OPENING = '-----BEGIN CERTIFICATE-----';
    private const CERTIFICATE_CLOSING = '-----END CERTIFICATE-----';

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

    /**
     * Reads a concatenated bundle back in. Anything outside the certificate armor is dropped, so the bag
     * attribute and subject and issuer lines `openssl pkcs12 -nokeys` writes ahead of each certificate are
     * tolerated and the bundle this returns carries the certificates alone.
     *
     * @throws InvalidPemBundle when the data holds no certificate, or holds private key material
     */
    public static function fromString(string $contents): self
    {
        if (preg_match('/-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----/', $contents) === 1) {
            throw InvalidPemBundle::containsPrivateKey();
        }

        $certificates = self::extract($contents);
        if (count($certificates) !== substr_count($contents, self::CERTIFICATE_OPENING)) {
            throw InvalidPemBundle::truncatedCertificate();
        }

        if ($certificates === []) {
            throw InvalidPemBundle::withoutCertificate();
        }

        return self::fromCertificates(...$certificates);
    }

    /**
     * @param non-empty-string $file
     *
     * @throws InvalidPemBundle when the file holds no certificate, or holds private key material
     */
    public static function fromFile(string $file): self
    {
        return self::fromString(read($file));
    }

    /**
     * The individual certificates the bundle carries, in the order they appear.
     *
     * @return list<Certificate>
     */
    public function certificates(): array
    {
        return self::extract($this->value);
    }

    public function toString(): string
    {
        return $this->value;
    }

    /**
     * @return list<Certificate>
     */
    private static function extract(string $contents): array
    {
        $matches = [];
        preg_match_all('/'.self::CERTIFICATE_OPENING.'.*?'.self::CERTIFICATE_CLOSING.'/s', $contents, $matches);

        $certificates = [];
        foreach ($matches[0] ?? [] as $block) {
            $certificates[] = new Certificate($block."\n");
        }

        return $certificates;
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
