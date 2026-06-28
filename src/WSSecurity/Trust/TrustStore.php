<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Trust;

use SensitiveParameter;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\Pkcs12Exception;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Pkcs12Bundle;
use function Psl\File\read;

/**
 * The set of trust anchors / pinned certificates the inbound verifier is willing to accept. A credential
 * value object with no openssl here; the chain validation against these anchors lives in OpenSSL\CertificateTrust.
 */
final class TrustStore
{
    /** @var list<Certificate> */
    private readonly array $anchors;

    private function __construct(Certificate ...$anchors)
    {
        $this->anchors = array_values($anchors);
    }

    public static function fromCertificates(Certificate ...$anchors): self
    {
        return new self(...$anchors);
    }

    /**
     * Builds the trust anchors from the CA chain embedded in a PKCS#12 blob. A store with zero anchors is
     * unusable, so a blob without an embedded chain is rejected rather than returned as an empty store.
     */
    public static function fromPkcs12(#[SensitiveParameter] string $contents, #[SensitiveParameter] string $passphrase = ''): self
    {
        $bundle = Pkcs12Bundle::read($contents, $passphrase);
        if ($bundle->caChain === []) {
            throw Pkcs12Exception::withoutCaChain();
        }

        return new self(...array_map(
            static fn (string $pem): Certificate => new Certificate($pem),
            $bundle->caChain,
        ));
    }

    /**
     * @param non-empty-string $file
     */
    public static function fromPkcs12File(string $file, #[SensitiveParameter] string $passphrase = ''): self
    {
        return self::fromPkcs12(read($file), $passphrase);
    }

    /**
     * @return list<Certificate>
     */
    public function anchors(): array
    {
        return $this->anchors;
    }

    public function isEmpty(): bool
    {
        return $this->anchors === [];
    }
}
