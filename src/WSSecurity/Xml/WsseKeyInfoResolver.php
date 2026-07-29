<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\ElementName;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\SameDocumentId;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\CertificateReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\KeyIdentifierKind;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\KeyInfoResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\OnlyChild;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\X509DataKeyInfoResolver;
use VeeWee\Xml\Dom\Document;

/**
 * The WS-Security KeyInfoResolver: reads the shapes the X.509 Token Profile defines, all of which hang off a
 * wsse:SecurityTokenReference. A direct reference to a wsse:BinarySecurityToken carrying one certificate or a
 * whole certification path; a wsse:KeyIdentifier holding a Subject Key Identifier or a SHA-1 thumbprint; and a
 * ds:X509IssuerSerial naming the certificate by issuer and serial.
 *
 * A message with no wsse:SecurityTokenReference falls through to the plain XML-DSig reader, because a WS-Security
 * signature may perfectly well carry its certificate inline as ds:X509Data. Note which ds:X509Data this class
 * reads: the one *inside* the token reference. The one directly under ds:KeyInfo is plain XML-DSig and belongs to
 * the resolver behind this one.
 *
 * This is where the profile's ValueType URIs are translated into what they mean, so nothing downstream has to
 * know how WS-Security spells an identifier.
 */
final readonly class WsseKeyInfoResolver implements KeyInfoResolver
{
    private KeyInfoResolver $plain;

    public function __construct(?KeyInfoResolver $plain = null)
    {
        $this->plain = $plain ?? new X509DataKeyInfoResolver();
    }

    public function read(Document $document, Element $signatureElement, IdLookup $idLookup): CertificateReference
    {
        $keyInfo = OnlyChild::named($signatureElement, Namespaces::Ds, 'KeyInfo')
            ?? throw SignatureVerificationFailed::withReason('ds:KeyInfo is missing.');

        $str = OnlyChild::named($keyInfo, Namespaces::Wsse, 'SecurityTokenReference');
        if ($str === null) {
            return $this->plain->read($document, $signatureElement, $idLookup);
        }

        return $this->fromDirectReference($document, $str, $idLookup)
            ?? $this->fromKeyIdentifier($str)
            ?? $this->fromIssuerSerial($str)
            // The reference is present but names the certificate in no way this profile defines. Falling through
            // to the plain reader here would let an unreadable token reference be quietly ignored in favour of an
            // inline certificate sitting beside it, which is a different key than the sender pointed at.
            ?? throw SignatureVerificationFailed::withReason(
                'ds:KeyInfo does not carry the certificate in a supported form.',
            );
    }

    /**
     * Resolves wsse:Reference to its wsse:BinarySecurityToken and reports what the token carries: one
     * certificate, or a whole certification path when the token declares PKIPath. Null when no such reference is
     * present, so a sibling form can be tried; an unusable one is refused outright.
     */
    private function fromDirectReference(Document $document, Element $str, IdLookup $idLookup): ?CertificateReference
    {
        $reference = OnlyChild::named($str, Namespaces::Wsse, 'Reference');
        if ($reference === null) {
            return null;
        }

        $tokenId = SameDocumentId::parse((string) $reference->getAttribute('URI'))
            ?? throw SignatureVerificationFailed::withReason('The token reference URI is not a same-document id.');

        try {
            $token = $idLookup->lookup($document, $tokenId);
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
     * Reads a wsse:KeyIdentifier naming the certificate by Subject Key Identifier or SHA-1 thumbprint.
     *
     * The element belongs in WSSE 1.0 whatever its ValueType, but the 1.1 namespace is also accepted: earlier
     * releases of this library emitted a Thumbprint reference that way, and a response correlated to one of those
     * must still verify. Only one may be present, across both namespaces.
     */
    private function fromKeyIdentifier(Element $str): ?CertificateReference
    {
        $wsse = OnlyChild::named($str, Namespaces::Wsse, 'KeyIdentifier');
        $wsse11 = OnlyChild::named($str, Namespaces::Wsse11, 'KeyIdentifier');

        if ($wsse !== null && $wsse11 !== null) {
            throw SignatureVerificationFailed::withReason('wsse:KeyIdentifier must appear at most once in its parent.');
        }

        $keyIdentifier = $wsse ?? $wsse11;
        if ($keyIdentifier === null) {
            return null;
        }

        $reference = ElementText::trimmed($keyIdentifier);
        if ($reference === '') {
            throw SignatureVerificationFailed::withReason('The key identifier is empty.');
        }

        return CertificateReference::keyIdentifier(
            $this->keyIdentifierKind((string) $keyIdentifier->getAttribute('ValueType')),
            $reference,
        );
    }

    /**
     * Translates the profile's ValueType URI into the identifier it names. A spelling this library does not
     * support is refused here: past this point the reference carries a kind, so an unsupported one has no way to
     * travel further and be refused for some later, less honest reason.
     */
    private function keyIdentifierKind(string $valueType): KeyIdentifierKind
    {
        return match (WsSecurityValueType::tryFrom($valueType)) {
            WsSecurityValueType::X509SubjectKeyIdentifier => KeyIdentifierKind::SubjectKeyIdentifier,
            WsSecurityValueType::ThumbprintSha1 => KeyIdentifierKind::ThumbprintSha1,
            default => throw SignatureVerificationFailed::withReason('The key identifier value type is unsupported.'),
        };
    }

    /**
     * Reads the ds:X509Data > ds:X509IssuerSerial inside the token reference into its issuer DN and decimal
     * serial. Null when the reference carries no such child.
     */
    private function fromIssuerSerial(Element $str): ?CertificateReference
    {
        $x509Data = OnlyChild::named($str, Namespaces::Ds, 'X509Data');
        if ($x509Data === null) {
            return null;
        }

        $issuerSerial = OnlyChild::named($x509Data, Namespaces::Ds, 'X509IssuerSerial');
        if ($issuerSerial === null) {
            return null;
        }

        $issuerName = OnlyChild::named($issuerSerial, Namespaces::Ds, 'X509IssuerName');
        $serialNumber = OnlyChild::named($issuerSerial, Namespaces::Ds, 'X509SerialNumber');
        if ($issuerName === null || $serialNumber === null) {
            throw SignatureVerificationFailed::withReason('The issuer-serial reference is incomplete.');
        }

        return CertificateReference::issuerSerial(
            ElementText::trimmed($issuerName),
            ElementText::trimmed($serialNumber),
        );
    }
}
