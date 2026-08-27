<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo;

use Dom\Element;
use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\PkiPath;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Throwable;
use VeeWee\Xml\Dom\Document;

/**
 * Turns whatever ds:KeyInfo names into the key the signature is verified with: a certificate chain, or the
 * symmetric secret the reference resolved to. Which shapes are recognised is the injected KeyInfoResolver's
 * business, not this class's: some carry the certificate in the message and are decoded here, the identifier
 * forms carry only a pointer and are resolved by matching the identifier against the trust store the caller
 * already holds, and a secret arrives already resolved because nothing local could look one up by identifier.
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
 * This class orchestrates: the injected KeyInfoResolver turns the DOM into a typed certificate reference, and
 * either the carried bytes are rewrapped into a chain or the TrustStoreCertificateResolver resolves the
 * identifier form. Which ds:KeyInfo shapes are understood is therefore the resolver's business, not this one's.
 */
final class VerificationKeyExtractor
{
    private readonly TrustStoreCertificateResolver $resolver;

    /**
     * The id lookup is held only to hand to the resolver, which needs it to follow a token reference. Wiring the
     * two together here is what keeps a resolver that reads wsu:Id from being paired with a lookup that resolves
     * something else.
     */
    public function __construct(
        private readonly KeyInfoResolver $keyInfo,
        private readonly IdLookup $idLookup,
    ) {
        $this->resolver = new TrustStoreCertificateResolver();
    }

    /**
     * @throws SignatureVerificationFailed when ds:KeyInfo is absent or carries an unsupported or malformed
     *         reference, or names a certificate the trust store does not hold
     */
    public function extract(
        Document $document,
        Element $signatureElement,
        TrustStore $trustStore,
    ): CertificateChain|SessionKey {
        $reference = $this->readKeyInfo($document, $signatureElement);

        if ($reference instanceof SecretReference) {
            return $reference->secret;
        }

        if (!$reference instanceof CertificateReference) {
            // The interface is a closed set of two, so this is the "a new kind arrived and nothing here was
            // taught to handle it" case rather than a reachable message shape.
            throw SignatureVerificationFailed::withReason('ds:KeyInfo does not carry the key in a supported form.');
        }

        if ($reference->form === CertificateReference::FORM_CARRIED) {
            return $this->carriedChain($reference->base64DerCertificates);
        }

        if ($reference->form === CertificateReference::FORM_CARRIED_PATH) {
            return $this->carriedPathChain($reference->base64DerCertificates[0] ?? '');
        }

        return CertificateChain::fromCertificates($this->resolver->resolve($reference, $trustStore));
    }

    /**
     * Reads ds:KeyInfo through the configured resolver, collapsing anything it throws into the one verification
     * failure. A resolver is a replaceable seam, so without this a third-party one could raise a type of its own
     * and tell a peer which shape of ds:KeyInfo its message failed on -- the sort of difference the uniform fault
     * exists to deny. The original is chained for the operator log only.
     *
     * @throws SignatureVerificationFailed
     */
    private function readKeyInfo(Document $document, Element $signatureElement): KeyReference
    {
        try {
            return $this->keyInfo->read($document, $signatureElement, $this->idLookup);
        } catch (SignatureVerificationFailed $failure) {
            throw $failure;
        } catch (Throwable $foreign) {
            throw SignatureVerificationFailed::withReason('ds:KeyInfo could not be read.', $foreign);
        }
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
     * code relying on that: the end-entity is derived, which is also what makes the sibling PKCS#7 form. Whose
     * order the profile says carries no meaning, and which stays tractable should it ever be accepted.
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
