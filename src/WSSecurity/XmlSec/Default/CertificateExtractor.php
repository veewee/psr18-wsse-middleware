<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\CertificateChain;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdResolver;
use VeeWee\Xml\Dom\Document;

/**
 * Reads the signer's certificate from ds:KeyInfo. Only the two inbound forms that carry the certificate inside
 * the message are supported: a direct BST reference (wsse:SecurityTokenReference > wsse:Reference pointing at a
 * wsse:BinarySecurityToken) and inline ds:X509Data > ds:X509Certificate. Forms that name the certificate by
 * identifier without carrying it are refused.
 *
 * The returned chain is not yet trusted; establishing trust is a separate step.
 */
final class CertificateExtractor
{
    private const X509V3_VALUE_TYPE
        = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';

    /**
     * @throws SignatureVerificationFailed when ds:KeyInfo is absent or carries an unsupported or malformed
     *         certificate reference
     */
    public function extract(Document $document, Element $signatureElement): CertificateChain
    {
        $keyInfo = $this->onlyChild($signatureElement, WsseNamespace::Ds->value, 'KeyInfo');
        if ($keyInfo === null) {
            throw SignatureVerificationFailed::withReason('ds:KeyInfo is missing.');
        }

        $base64Der = $this->fromSecurityTokenReference($document, $keyInfo)
            ?? $this->fromInlineX509($keyInfo);

        if ($base64Der === null) {
            throw SignatureVerificationFailed::withReason(
                'ds:KeyInfo does not carry the certificate in a supported form.',
            );
        }

        return CertificateChain::fromCertificates($this->certificateFromBase64Der($base64Der));
    }

    /**
     * Resolves a wsse:SecurityTokenReference > wsse:Reference to its wsse:BinarySecurityToken and returns the
     * token's base64 body. Returns null when KeyInfo uses no SecurityTokenReference at all (so the inline form
     * can be tried), but refuses an unsupported reference shape outright.
     */
    private function fromSecurityTokenReference(Document $document, Element $keyInfo): ?string
    {
        $str = $this->onlyChild($keyInfo, WsseNamespace::Wsse->value, 'SecurityTokenReference');
        if ($str === null) {
            return null;
        }

        $reference = $this->onlyChild($str, WsseNamespace::Wsse->value, 'Reference');
        if ($reference === null) {
            // A SecurityTokenReference without a wsse:Reference names the cert by identifier (KeyIdentifier,
            // X509Data/IssuerSerial, ...): not carried in the message, so unsupported here.
            throw SignatureVerificationFailed::withReason(
                'The SecurityTokenReference does not carry the certificate.',
            );
        }

        $uri = (string) $reference->getAttribute('URI');
        if (!str_starts_with($uri, '#') || $uri === '#') {
            throw SignatureVerificationFailed::withReason('The token reference URI is not a same-document id.');
        }

        $tokenId = substr($uri, 1);

        try {
            $token = WsuIdResolver::resolve($document, $tokenId);
        } catch (IdReferenceException) {
            throw SignatureVerificationFailed::withReason('The referenced security token was not found.');
        }

        if ($token->localName !== 'BinarySecurityToken' || $token->namespaceURI !== WsseNamespace::Wsse->value) {
            throw SignatureVerificationFailed::withReason('The token reference does not point at a BinarySecurityToken.');
        }

        if ($token->getAttribute('ValueType') !== self::X509V3_VALUE_TYPE) {
            throw SignatureVerificationFailed::withReason('The BinarySecurityToken value type is unsupported.');
        }

        return trim((string) $token->textContent);
    }

    /**
     * Reads an inline ds:X509Data > ds:X509Certificate. Returns null when KeyInfo carries no ds:X509Data so the
     * caller can refuse with a uniform message.
     */
    private function fromInlineX509(Element $keyInfo): ?string
    {
        $x509Data = $this->onlyChild($keyInfo, WsseNamespace::Ds->value, 'X509Data');
        if ($x509Data === null) {
            return null;
        }

        $certificate = $this->onlyChild($x509Data, WsseNamespace::Ds->value, 'X509Certificate');
        if ($certificate === null) {
            throw SignatureVerificationFailed::withReason('ds:X509Data does not carry a ds:X509Certificate.');
        }

        return trim((string) $certificate->textContent);
    }

    private function certificateFromBase64Der(string $base64Der): Certificate
    {
        $der = base64_decode($base64Der, true);
        if ($der === false || $der === '') {
            throw SignatureVerificationFailed::withReason('The certificate bytes are not valid base64.');
        }

        // The token body is the base64 of a DER certificate; rewrap it as PEM, the form the OpenSSL boundary
        // reads. Malformed bytes are caught later when the certificate is loaded for trust and verification.
        $pem = "-----BEGIN CERTIFICATE-----\n"
            .chunk_split(base64_encode($der), 64, "\n")
            .'-----END CERTIFICATE-----'."\n";

        return new Certificate($pem);
    }

    private function onlyChild(Element $parent, string $namespaceUri, string $localName): ?Element
    {
        $found = null;
        foreach ($parent->childNodes as $child) {
            if (!$child instanceof Element) {
                continue;
            }

            if ($child->localName !== $localName || $child->namespaceURI !== $namespaceUri) {
                continue;
            }

            if ($found !== null) {
                throw SignatureVerificationFailed::withReason(
                    sprintf('%s must appear at most once in its parent.', $localName),
                );
            }

            $found = $child;
        }

        return $found;
    }
}
