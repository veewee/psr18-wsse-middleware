<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore;

use Phpro\ResourceStream\Factory\TmpStream;
use Phpro\ResourceStream\ResourceStream;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidPemBundle;
use function Psl\File\read;

/**
 * The contents of a PEM file: one or more certificates, and the private key sitting alongside them if the file
 * carries one. This is the form both a trusted-CA file and a combined certificate-and-key file take.
 *
 * The bundle string this exposes is rebuilt from the certificates alone, so key material never reaches
 * toString() or the temp file toResource() writes. A key that was present is handed back separately, through
 * privateKey().
 */
final readonly class Pem
{
    private const ARMOR_OPENING = '-----BEGIN';
    private const CERTIFICATE_OPENING = '-----BEGIN CERTIFICATE-----';
    private const CERTIFICATE_CLOSING = '-----END CERTIFICATE-----';
    private const PRIVATE_KEY_OPENING = '/-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----/';
    private const PRIVATE_KEY_BLOCK = '/-----BEGIN ([A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*)-----.*?-----END \1-----/s';

    private function __construct(
        private string $value,
        private ?Key $privateKey,
    ) {
    }

    public static function fromCertificates(Certificate ...$certificates): self
    {
        return new self(self::concatenate(...$certificates), null);
    }

    /**
     * Reads a PEM file back in, whatever it holds. Anything outside the armor is dropped, so the bag attribute
     * and subject and issuer lines `openssl pkcs12 -nokeys` writes ahead of each certificate are tolerated.
     *
     * A private key among the certificates is read out rather than refused: PEM is only a container, and which
     * files may carry one is not this reader's call to make. TrustStore::fromPem() is where a key means the
     * wrong file was exported, and it is the one that says so.
     *
     * @throws InvalidPemBundle when the data holds no certificate, is truncated, or carries several keys
     */
    public static function fromString(#[SensitiveParameter] string $contents): self
    {
        $certificates = self::certificatesIn($contents);

        return new self(self::concatenate(...$certificates), self::extractPrivateKey($contents));
    }

    /**
     * The certificates in raw PEM data, with no attention paid to any key material alongside them. A caller
     * that wants the certificates alone uses this, so a defect in the key cannot surface as a failure to read
     * a certificate: the two are separate questions and answering one must not fail over the other.
     *
     * @return non-empty-list<Certificate>
     *
     * @throws InvalidPemBundle when the data holds no certificate, or a certificate block is truncated or
     *         carries nested armor
     */
    public static function certificatesIn(#[SensitiveParameter] string $contents): array
    {
        $certificates = self::extractPublicCertificates($contents);
        if (count($certificates) !== substr_count($contents, self::CERTIFICATE_OPENING)) {
            throw InvalidPemBundle::truncatedCertificate();
        }

        if ($certificates === []) {
            throw InvalidPemBundle::withoutCertificate();
        }

        return $certificates;
    }

    /**
     * @param non-empty-string $file
     *
     * @throws InvalidPemBundle when the file holds no certificate, is truncated, or carries several keys
     */
    public static function fromFile(string $file): self
    {
        return self::fromString(read($file));
    }

    /**
     * The individual certificates the file carries, in the order they appear. That order carries no meaning:
     * a converted Java truststore lists unrelated anchors, so callers that need an end-entity certificate
     * derive it with CertificateChain::fromUnorderedCertificates() rather than taking the first.
     *
     * @return list<Certificate>
     */
    public function certificates(): array
    {
        return self::extractPublicCertificates($this->value);
    }

    /**
     * The private key the file carried, or null when it held certificates alone. A trusted-CA file has none;
     * a combined certificate-and-key file has one.
     */
    public function privateKey(): ?Key
    {
        return $this->privateKey;
    }

    /**
     * The certificates concatenated into one bundle. Never the private key, whatever the file held.
     */
    public function toString(): string
    {
        return $this->value;
    }

    /**
     * @return list<Certificate>
     *
     * @throws InvalidPemBundle when a certificate block carries nested armor
     */
    private static function extractPublicCertificates(string $contents): array
    {
        $matches = [];
        preg_match_all('/'.self::CERTIFICATE_OPENING.'.*?'.self::CERTIFICATE_CLOSING.'/s', $contents, $matches);

        $certificates = [];
        foreach ($matches[0] ?? [] as $block) {
            if (self::hasNestedArmor($block, self::CERTIFICATE_OPENING)) {
                throw InvalidPemBundle::nestedArmor();
            }

            $certificates[] = new Certificate($block."\n");
        }

        return $certificates;
    }

    /**
     * The single private key in the data, if there is one. The two armor lines have to name the same key type:
     * otherwise the block would be read as spanning whatever happened to sit between a mismatched pair.
     *
     * @throws InvalidPemBundle
     */
    private static function extractPrivateKey(#[SensitiveParameter] string $contents): ?Key
    {
        $matches = [];
        preg_match_all(self::PRIVATE_KEY_BLOCK, $contents, $matches);
        $blocks = $matches[0] ?? [];
        $labels = $matches[1] ?? [];

        foreach ($blocks as $index => $block) {
            if (self::hasNestedArmor($block, '-----BEGIN '.($labels[$index] ?? '').'-----')) {
                throw InvalidPemBundle::nestedArmor();
            }
        }

        // An opening with no matching close is refused rather than skipped, for the same reason a truncated
        // certificate is: a half-transferred file would otherwise load as an identity quietly missing its key.
        if (count($blocks) !== (int) preg_match_all(self::PRIVATE_KEY_OPENING, $contents)) {
            throw InvalidPemBundle::truncatedPrivateKey();
        }

        if (count($blocks) > 1) {
            throw InvalidPemBundle::withMultiplePrivateKeys();
        }

        return $blocks === [] ? null : new Key($blocks[0]."\n");
    }

    /**
     * Whether a block's body opens another one. Both block patterns stop at the first matching close, so a
     * block that opens a second one is a block whose own close is missing and whose content belongs to
     * something else. Taking either kind whole is what would let a nested key ride into the bundle string,
     * or a certificate ride into the key, so the two sides ask the same question here rather than each
     * carrying its own answer.
     */
    private static function hasNestedArmor(string $block, string $opening): bool
    {
        return str_contains(substr($block, strlen($opening)), self::ARMOR_OPENING);
    }

    private static function concatenate(Certificate ...$certificates): string
    {
        return implode("\n", array_map(
            static fn (Certificate $certificate): string => $certificate->contents(),
            $certificates,
        ));
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
