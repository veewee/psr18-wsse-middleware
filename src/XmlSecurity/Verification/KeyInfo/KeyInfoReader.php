<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\ElementName;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\SameDocumentId;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\WsSecurityEncodingType;
use Soap\Psr18WsseMiddleware\XmlSecurity\WsSecurityValueType;
use Soap\Psr18WsseMiddleware\XmlSecurity\XmlIdLookup;
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
    public function __construct(
        private IdLookup $idLookup = new XmlIdLookup(),
    ) {
    }

    /**
     * @throws SignatureVerificationFailed when ds:KeyInfo is absent or carries an unsupported or malformed
     *         certificate reference
     */
    public function read(Document $document, Element $signatureElement): CertificateReference
    {
        $keyInfo = $this->onlyChild($signatureElement, Namespaces::Ds, 'KeyInfo');
        if ($keyInfo === null) {
            throw SignatureVerificationFailed::withReason('ds:KeyInfo is missing.');
        }

        $fromToken = $this->fromSecurityTokenReference($document, $keyInfo);
        if ($fromToken !== null) {
            return $fromToken;
        }

        $inline = $this->fromInlineX509($keyInfo);
        if ($inline !== []) {
            return CertificateReference::carried(...$inline);
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
     * Resolves a wsse:SecurityTokenReference > wsse:Reference to its wsse:BinarySecurityToken and reports what
     * the token carries: one certificate, or a whole certification path when the token declares PKIPath.
     * Returns null when KeyInfo carries no wsse:Reference at all (so an identifier form or the inline form can
     * be tried), but refuses an unsupported reference shape outright.
     */
    private function fromSecurityTokenReference(Document $document, Element $keyInfo): ?CertificateReference
    {
        $str = $this->onlyChild($keyInfo, Namespaces::Wsse, 'SecurityTokenReference');
        if ($str === null) {
            return null;
        }

        $reference = $this->onlyChild($str, Namespaces::Wsse, 'Reference');
        if ($reference === null) {
            // No direct reference: the certificate is not carried by a BST here. The identifier forms are tried
            // by the caller; this method only owns the carried-by-BST path.
            return null;
        }

        $tokenId = SameDocumentId::parse((string) $reference->getAttribute('URI'))
            ?? throw SignatureVerificationFailed::withReason('The token reference URI is not a same-document id.');

        try {
            $token = $this->idLookup->lookup($document, $tokenId);
        } catch (IdReferenceException) {
            throw SignatureVerificationFailed::withReason('The referenced security token was not found.');
        }

        if (!ElementName::matches($token, Namespaces::Wsse, 'BinarySecurityToken')) {
            throw SignatureVerificationFailed::withReason('The token reference does not point at a BinarySecurityToken.');
        }

        $valueType = WsSecurityValueType::tryFrom((string) $token->getAttribute('ValueType'));
        if ($valueType !== WsSecurityValueType::X509v3 && $valueType !== WsSecurityValueType::X509PKIPathv1) {
            throw SignatureVerificationFailed::withReason('The BinarySecurityToken value type is unsupported.');
        }

        // The encoding type is optional and defaults to base64; a present declaration must name that encoding,
        // since the token body is read as base64 regardless. An absent declaration is the conformant default.
        if ($token->hasAttribute('EncodingType')
            && $token->getAttribute('EncodingType') !== WsSecurityEncodingType::Base64Binary->value
        ) {
            throw SignatureVerificationFailed::withReason('The BinarySecurityToken encoding type is unsupported.');
        }

        $body = ElementText::trimmed($token);

        return $valueType === WsSecurityValueType::X509PKIPathv1
            ? CertificateReference::carriedPath($body)
            : CertificateReference::carried($body);
    }

    /**
     * Reads every inline ds:X509Data > ds:X509Certificate. XML-DSig allows more than one so a peer can carry
     * its whole certification path, so this returns all of them in document order — which says nothing about
     * which is the end-entity, a question the caller answers from issuer linkage. An empty list means KeyInfo
     * carries no inline certificate, leaving the caller to try an identifier form or refuse uniformly.
     *
     * @return list<string>
     */
    private function fromInlineX509(Element $keyInfo): array
    {
        $x509Data = $this->onlyChild($keyInfo, Namespaces::Ds, 'X509Data');
        if ($x509Data === null) {
            return [];
        }

        return array_map(
            static fn (Element $certificate): string => ElementText::trimmed($certificate),
            ChildElements::named($x509Data, Namespaces::Ds, 'X509Certificate'),
        );
    }

    /**
     * Reads a reference that names the certificate by identifier (Subject Key Identifier, SHA-1 thumbprint, or
     * issuer DN plus serial). Returns null when KeyInfo carries no identifier reference so the caller can refuse
     * with a uniform message.
     */
    private function fromIdentifierReference(Element $keyInfo): ?CertificateReference
    {
        $str = $this->onlyChild($keyInfo, Namespaces::Wsse, 'SecurityTokenReference');
        if ($str === null) {
            return null;
        }

        $keyIdentifier = $this->onlyKeyIdentifier($str);
        if ($keyIdentifier !== null) {
            $reference = ElementText::trimmed($keyIdentifier);
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
     * Reads the at-most-one wsse:KeyIdentifier child. The element belongs in WSSE 1.0 whatever its ValueType,
     * but the 1.1 namespace is also accepted: earlier releases of this library emitted a Thumbprint reference
     * that way, and a response correlated to one of those must still verify. Only one may be present.
     */
    private function onlyKeyIdentifier(Element $str): ?Element
    {
        $wsse = $this->onlyChild($str, Namespaces::Wsse, 'KeyIdentifier');
        $wsse11 = $this->onlyChild($str, Namespaces::Wsse11, 'KeyIdentifier');

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
        $x509Data = $this->onlyChild($str, Namespaces::Ds, 'X509Data');
        if ($x509Data === null) {
            return null;
        }

        $issuerSerial = $this->onlyChild($x509Data, Namespaces::Ds, 'X509IssuerSerial');
        if ($issuerSerial === null) {
            return null;
        }

        $issuerName = $this->onlyChild($issuerSerial, Namespaces::Ds, 'X509IssuerName');
        $serialNumber = $this->onlyChild($issuerSerial, Namespaces::Ds, 'X509SerialNumber');
        if ($issuerName === null || $serialNumber === null) {
            throw SignatureVerificationFailed::withReason('The issuer-serial reference is incomplete.');
        }

        return CertificateReference::issuerSerial(
            ElementText::trimmed($issuerName),
            ElementText::trimmed($serialNumber),
        );
    }

    private function onlyChild(Element $parent, Namespaces $namespace, string $localName): ?Element
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
