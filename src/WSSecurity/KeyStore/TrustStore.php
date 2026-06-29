<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore;

use Soap\Psr18WsseMiddleware\WSSecurity\Exception\Pkcs12Exception;

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
     * Builds the trust anchors from the CA chain embedded in an already-decoded PKCS#12 bundle. A store with
     * zero anchors is unusable, so a bundle without an embedded chain is rejected rather than returned empty.
     */
    public static function fromPkcs12(Pkcs12Bundle $bundle): self
    {
        $caCertificates = array_slice($bundle->chain->all(), 1);
        if ($caCertificates === []) {
            throw Pkcs12Exception::withoutCaChain();
        }

        return new self(...$caCertificates);
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

    /**
     * The anchors concatenated into one PEM bundle, the trusted-CA file a chain-to-anchor check loads.
     */
    public function toPem(): string
    {
        return implode("\n", array_map(static fn (Certificate $certificate): string => $certificate->contents(), $this->anchors));
    }
}
