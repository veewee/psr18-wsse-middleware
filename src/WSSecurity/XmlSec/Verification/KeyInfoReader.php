<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdResolver;
use VeeWee\Xml\Dom\Document;

/**
 * Reads ds:KeyInfo into a typed certificate reference, recognising the four inbound forms: a direct BST
 * reference (wsse:SecurityTokenReference > wsse:Reference at a wsse:BinarySecurityToken), an inline
 * ds:X509Data > ds:X509Certificate, a wsse:KeyIdentifier holding a Subject Key Identifier or a SHA-1
 * thumbprint, and a ds:X509IssuerSerial. The carried forms yield the certificate's base64 body; the
 * identifier forms yield only a pointer to be resolved against the trust store. Every single-transform,
 * no-duplicate and unsupported-shape rejection lives here so the orchestrator only dispatches on the result.
 */
final class KeyInfoReader
{
    private const X509V3_VALUE_TYPE
        = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
    private const BASE64_BINARY_ENCODING_TYPE
        = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    /**
     * @throws SignatureVerificationFailed when ds:KeyInfo is absent or carries an unsupported or malformed
     *         certificate reference
     */
    public function read(Document $document, Element $signatureElement): CertificateReference
    {
        $keyInfo = $this->onlyChild($signatureElement, WsseNamespace::Ds, 'KeyInfo');
        if ($keyInfo === null) {
            throw SignatureVerificationFailed::withReason('ds:KeyInfo is missing.');
        }

        $carried = $this->fromSecurityTokenReference($document, $keyInfo)
            ?? $this->fromInlineX509($keyInfo);
        if ($carried !== null) {
            return CertificateReference::carried($carried);
        }

        $identifier = $this->fromIdentifierReference($keyInfo);
        if ($identifier !== null) {
            return $identifier;
        }

        throw SignatureVerificationFailed::withReason(
            'ds:KeyInfo does not carry the certificate in a supported form.',
        );
    }

    /**
     * Resolves a wsse:SecurityTokenReference > wsse:Reference to its wsse:BinarySecurityToken and returns the
     * token's base64 body. Returns null when KeyInfo carries no wsse:Reference at all (so an identifier form or
     * the inline form can be tried), but refuses an unsupported reference shape outright.
     */
    private function fromSecurityTokenReference(Document $document, Element $keyInfo): ?string
    {
        $str = $this->onlyChild($keyInfo, WsseNamespace::Wsse, 'SecurityTokenReference');
        if ($str === null) {
            return null;
        }

        $reference = $this->onlyChild($str, WsseNamespace::Wsse, 'Reference');
        if ($reference === null) {
            // No direct reference: the certificate is not carried by a BST here. The identifier forms are tried
            // by the caller; this method only owns the carried-by-BST path.
            return null;
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

        // The encoding type is optional and defaults to base64; a present declaration must name that encoding,
        // since the token body is read as base64 regardless. An absent declaration is the conformant default.
        if ($token->hasAttribute('EncodingType')
            && $token->getAttribute('EncodingType') !== self::BASE64_BINARY_ENCODING_TYPE
        ) {
            throw SignatureVerificationFailed::withReason('The BinarySecurityToken encoding type is unsupported.');
        }

        return trim((string) $token->textContent);
    }

    /**
     * Reads an inline ds:X509Data > ds:X509Certificate. Returns null when KeyInfo carries no ds:X509Data so the
     * caller can try an identifier form or refuse with a uniform message.
     */
    private function fromInlineX509(Element $keyInfo): ?string
    {
        $x509Data = $this->onlyChild($keyInfo, WsseNamespace::Ds, 'X509Data');
        if ($x509Data === null) {
            return null;
        }

        $certificate = $this->onlyChild($x509Data, WsseNamespace::Ds, 'X509Certificate');
        if ($certificate === null) {
            return null;
        }

        return trim((string) $certificate->textContent);
    }

    /**
     * Reads a reference that names the certificate by identifier (Subject Key Identifier, SHA-1 thumbprint, or
     * issuer DN plus serial). Returns null when KeyInfo carries no identifier reference so the caller can refuse
     * with a uniform message.
     */
    private function fromIdentifierReference(Element $keyInfo): ?CertificateReference
    {
        $str = $this->onlyChild($keyInfo, WsseNamespace::Wsse, 'SecurityTokenReference');
        if ($str === null) {
            return null;
        }

        $keyIdentifier = $this->onlyKeyIdentifier($str);
        if ($keyIdentifier !== null) {
            $reference = trim((string) $keyIdentifier->textContent);
            if ($reference === '') {
                throw SignatureVerificationFailed::withReason('The key identifier is empty.');
            }

            return CertificateReference::keyIdentifier(
                (string) $keyIdentifier->getAttribute('ValueType'),
                $reference,
            );
        }

        $issuerSerial = $this->issuerSerialReference($str);
        if ($issuerSerial !== null) {
            return $issuerSerial;
        }

        return null;
    }

    /**
     * Reads the at-most-one wsse:KeyIdentifier child. The element lives in either the WSSE 1.0 or the WSSE 1.1
     * namespace depending on the ValueType, so both are accepted but only one may be present.
     */
    private function onlyKeyIdentifier(Element $str): ?Element
    {
        $wsse = $this->onlyChild($str, WsseNamespace::Wsse, 'KeyIdentifier');
        $wsse11 = $this->onlyChild($str, WsseNamespace::Wsse11, 'KeyIdentifier');

        if ($wsse !== null && $wsse11 !== null) {
            throw SignatureVerificationFailed::withReason('wsse:KeyIdentifier must appear at most once in its parent.');
        }

        return $wsse ?? $wsse11;
    }

    /**
     * Reads a ds:X509Data > ds:X509IssuerSerial reference into its issuer DN and decimal serial. Returns null
     * when no such reference is present.
     */
    private function issuerSerialReference(Element $str): ?CertificateReference
    {
        $x509Data = $this->onlyChild($str, WsseNamespace::Ds, 'X509Data');
        if ($x509Data === null) {
            return null;
        }

        $issuerSerial = $this->onlyChild($x509Data, WsseNamespace::Ds, 'X509IssuerSerial');
        if ($issuerSerial === null) {
            return null;
        }

        $issuerName = $this->onlyChild($issuerSerial, WsseNamespace::Ds, 'X509IssuerName');
        $serialNumber = $this->onlyChild($issuerSerial, WsseNamespace::Ds, 'X509SerialNumber');
        if ($issuerName === null || $serialNumber === null) {
            throw SignatureVerificationFailed::withReason('The issuer-serial reference is incomplete.');
        }

        return CertificateReference::issuerSerial(
            trim((string) $issuerName->textContent),
            trim((string) $serialNumber->textContent),
        );
    }

    private function onlyChild(Element $parent, WsseNamespace $namespace, string $localName): ?Element
    {
        $matches = ChildElements::named($parent, $namespace, $localName);
        if (count($matches) > 1) {
            throw SignatureVerificationFailed::withReason(
                sprintf('%s must appear at most once in its parent.', $localName),
            );
        }

        return $matches[0] ?? null;
    }
}
