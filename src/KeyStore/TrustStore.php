<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore;

use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidTrustStore;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\Pkcs12Exception;

/**
 * The set of trust anchors / pinned certificates the inbound verifier is willing to accept, and optionally the
 * revocation lists it checks signers against. A credential value object with no openssl here; the chain
 * validation against these anchors lives in OpenSSL\CertificateTrust.
 *
 * Anchors and revocation lists belong together because a CRL is only believed once its own signature verifies
 * against one of these anchors.
 */
final class TrustStore
{
    /** @var list<Certificate> */
    private readonly array $anchors;

    /** @var list<CertificateRevocationList> */
    private array $revocationLists = [];

    private function __construct(Certificate ...$anchors)
    {
        $this->anchors = array_values($anchors);
    }

    public static function fromCertificates(Certificate ...$anchors): self
    {
        return new self(...$anchors);
    }

    /**
     * Builds the trust anchors from a PEM bundle, the form a trusted-CA file carries. Every certificate in the
     * bundle is an anchor: unlike a PKCS#12 identity bundle there is no end-entity certificate to skip, so a
     * bundle of thirty anchors yields thirty. A store with zero anchors is unusable and is rejected.
     *
     * A bundle that also carries a private key is refused. Pem reads such a file happily, because PEM is only
     * a container, but a key in a file destined for a trust store means the wrong file was exported.
     *
     * @throws InvalidTrustStore when the bundle carries a private key, or no certificate
     */
    public static function fromPem(Pem $bundle): self
    {
        if ($bundle->privateKey() !== null) {
            throw InvalidTrustStore::withPrivateKey();
        }

        $anchors = $bundle->certificates();
        if ($anchors === []) {
            throw InvalidTrustStore::withoutAnchors();
        }

        return new self(...$anchors);
    }

    /**
     * Builds the trust anchors from the CA chain embedded in an already-decoded PKCS#12 bundle. The input is an
     * identity bundle (a leaf certificate with its private key), so entry 0 is that leaf and is deliberately
     * skipped; only the certificates above it are anchors. A store with zero anchors is unusable, so a bundle
     * without an embedded chain is rejected rather than returned empty.
     *
     * A Java truststore converted with keytool is not this shape: it has no leaf and no key. Load it as a PEM
     * bundle through fromPem() instead, which keeps every certificate.
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
     * Turns on revocation checking with the lists to check against. Off by default, matching the peer default
     * (WSS4J ships ENABLE_REVOCATION=false), because it needs material only the integrator can supply.
     *
     * Once on, the check is fail-closed: a signer whose issuer no supplied list covers is rejected, as is one
     * covered by a list that is stale or not signed by an anchor. Nothing here fetches over the network, so
     * enabling this adds no I/O and no new timeout to the verification path.
     *
     * @throws InvalidTrustStore when revocation is required with no list to check against
     */
    public function withRevocationLists(CertificateRevocationList ...$revocationLists): self
    {
        if ($revocationLists === []) {
            throw InvalidTrustStore::withoutRevocationLists();
        }

        $clone = clone $this;
        $clone->revocationLists = array_values($revocationLists);

        return $clone;
    }

    /**
     * @return list<Certificate>
     */
    public function anchors(): array
    {
        return $this->anchors;
    }

    /**
     * @return list<CertificateRevocationList>
     */
    public function revocationLists(): array
    {
        return $this->revocationLists;
    }

    public function checksRevocation(): bool
    {
        return $this->revocationLists !== [];
    }

    public function isEmpty(): bool
    {
        return $this->anchors === [];
    }

    /**
     * The anchors concatenated into one PEM bundle, the trusted-CA file a chain-to-anchor check loads.
     */
    public function toPem(): Pem
    {
        return Pem::fromCertificates(...$this->anchors);
    }
}
