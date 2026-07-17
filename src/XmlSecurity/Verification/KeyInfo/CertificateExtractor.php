<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
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
            try {
                $certificate = Certificate::fromBase64Der($reference->base64Der);
            } catch (InvalidCertificate) {
                throw SignatureVerificationFailed::withReason('The certificate bytes are not valid base64.');
            }

            return CertificateChain::fromCertificates($certificate);
        }

        return CertificateChain::fromCertificates($this->resolver->resolve($reference, $trustStore));
    }
}
