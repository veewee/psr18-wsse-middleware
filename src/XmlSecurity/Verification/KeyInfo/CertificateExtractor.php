<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo;

use Dom\Element;
use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\PkiPath;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\XmlIdLookup;
use VeeWee\Xml\Dom\Document;

/**
 * Reads the signer's certificate from ds:KeyInfo. Two inbound forms carry the certificate inside the message: a
 * direct BST reference (wsse:SecurityTokenReference > wsse:Reference pointing at a wsse:BinarySecurityToken) and
 * an inline ds:X509Data > ds:X509Certificate. A third group names the certificate by identifier without carrying
 * it: a wsse:KeyIdentifier holding a Subject Key Identifier or a SHA-1 thumbprint, or a ds:X509IssuerSerial.
 * Those references are resolved by matching the identifier against the trust store the caller already holds.
 *
 * Resolving by identifier requires the actual certificate to be available locally, since the message carries
 * only a pointer to it. The trust store is the only local source of candidate certificates, so an identifier
 * that does not match any trust store entry cannot be resolved and is refused. That mirrors how conformant
 * verifiers require the certificate to live in a local store before an identifier reference can name it; a
 * trust store holding only a CA, not the signer leaf, cannot satisfy such a reference.
 *
 * The returned chain is not yet trusted; establishing trust is a separate step. A certificate resolved from the
 * trust store still flows through that step unchanged.
 *
 * This class orchestrates: the KeyInfoReader turns the DOM into a typed certificate reference, and either the
 * carried bytes are rewrapped into a chain or the TrustStoreCertificateResolver resolves the identifier form.
 */
final class CertificateExtractor
{
    private readonly KeyInfoReader $reader;
    private readonly TrustStoreCertificateResolver $resolver;

    public function __construct(IdLookup $idLookup = new XmlIdLookup())
    {
        $this->reader = new KeyInfoReader($idLookup);
        $this->resolver = new TrustStoreCertificateResolver();
    }

    /**
     * @throws SignatureVerificationFailed when ds:KeyInfo is absent or carries an unsupported or malformed
     *         certificate reference, or names a certificate the trust store does not hold
     */
    public function extract(Document $document, Element $signatureElement, TrustStore $trustStore): CertificateChain
    {
        $reference = $this->reader->read($document, $signatureElement);

        if ($reference->form === CertificateReference::FORM_CARRIED) {
            return $this->carriedChain($reference->base64DerCertificates);
        }

        if ($reference->form === CertificateReference::FORM_CARRIED_PATH) {
            return $this->carriedPathChain($reference->base64DerCertificates[0] ?? '');
        }

        return CertificateChain::fromCertificates($this->resolver->resolve($reference, $trustStore));
    }

    /**
     * Decodes the certificates the message carries and hands the ordering to CertificateChain, which derives
     * the end-entity. Every malformed or unorderable set collapses into the one uniform failure. The path
     * length is deliberately not bounded: no specification states a maximum, a certificate costs one parse
     * rather than any per-item crypto, and a junk path is refused anyway for having no single end-entity or
     * for not reaching a trust anchor.
     *
     * @param list<string> $base64DerCertificates
     *
     * @throws SignatureVerificationFailed
     */
    private function carriedChain(array $base64DerCertificates): CertificateChain
    {
        $certificates = [];
        foreach ($base64DerCertificates as $base64Der) {
            try {
                $certificates[] = Certificate::fromBase64Der($base64Der);
            } catch (InvalidCertificate) {
                throw SignatureVerificationFailed::withReason('The certificate bytes are not valid base64.');
            }
        }

        try {
            return CertificateChain::fromUnorderedCertificates(...$certificates);
        } catch (InvalidArgumentException | CryptoOperationFailed) {
            throw SignatureVerificationFailed::withReason('The carried certificate path could not be ordered.');
        }
    }

    /**
     * Unwraps a PKIPath token body into its certificates and orders them the same way, so a path token and an
     * inline path reach the trust check as the same shape. The profile calls a PKIPath ordered without this
     * code relying on that: the end-entity is derived, which is also what makes the sibling PKCS#7 form — whose
     * order the profile says carries no meaning — tractable should it ever be accepted.
     *
     * @throws SignatureVerificationFailed
     */
    private function carriedPathChain(string $base64DerPath): CertificateChain
    {
        $der = base64_decode(Certificate::normalizeBase64Der($base64DerPath), true);
        if ($der === false || $der === '') {
            throw SignatureVerificationFailed::withReason('The certificate path is not valid base64.');
        }

        try {
            return CertificateChain::fromUnorderedCertificates(...PkiPath::certificates($der));
        } catch (InvalidCertificate | InvalidArgumentException | CryptoOperationFailed) {
            throw SignatureVerificationFailed::withReason('The carried certificate path could not be read.');
        }
    }
}
