<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Dom\Element;
use Dom\XPath;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\SamlVersion;
use Soap\Psr18WsseMiddleware\Xml\ElementName;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\Query;
use Soap\Psr18WsseMiddleware\Xml\SameDocumentId;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\PrefixList;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\OnlyChild;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\DereferencingTransform;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\TransformCanonicalization;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Locator\Element\children;

/**
 * The WS-Security STR-Transform: a ds:Reference points at a wsse:SecurityTokenReference, and the digest was
 * computed over the security token that reference names rather than over the reference element.
 *
 * A peer signs its token this way so the signature covers the token reached *through* the reference, which is
 * what lets a receiver relocate or re-serialize the token and still verify. The bytes are the token's either
 * way; only the path to them differs.
 *
 * Two of the forms the profile allows are dereferenced here, both of which name an element the message
 * actually carries: a wsse:Reference to a token by id, and a wsse:KeyIdentifier naming a SAML assertion. The
 * remaining forms -- a Subject Key Identifier, a thumbprint, a ds:X509IssuerSerial -- name a certificate
 * rather than an element, and a signer that used one digested a wsse:BinarySecurityToken it built from its own
 * keystore, an element that never travelled. Rebuilding that byte-for-byte from a certificate found locally is
 * not attempted: those references are refused, because a digest over an approximation of what the signer
 * digested proves nothing.
 */
final class SecurityTokenReferenceTransform implements DereferencingTransform
{
    private const ALGORITHM = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform';

    /**
     * The prefix WSS4J pins on every STR-Transform digest, whatever the reference's own parameters say. It
     * canonicalizes the dereferenced token with a hardcoded '#default' inclusive prefix and default-namespace
     * propagation, so a verifier that leaves it out canonicalizes different bytes than the signer did.
     */
    private const DEFAULT_NAMESPACE_PREFIX = '#default';

    public function algorithm(): string
    {
        return self::ALGORITHM;
    }

    /**
     * The canonicalization is the transform's own, carried in wsse:TransformationParameters, and there is no
     * default to fall back on: WS-Security requires it and a digest cannot be recomputed without it. Whether
     * the method is acceptable at all stays with the policy enforcer, which gates every other reference's
     * canonicalization the same way, so an inclusive method named here is refused there rather than twice.
     */
    public function canonicalization(Element $transform): TransformCanonicalization
    {
        $parameters = OnlyChild::named($transform, WsseNamespaces::Wsse, 'TransformationParameters')
            ?? throw SignatureVerificationFailed::withReason(
                'An STR-Transform must carry wsse:TransformationParameters.',
            );

        $method = OnlyChild::named($parameters, Namespaces::Ds, 'CanonicalizationMethod')
            ?? throw SignatureVerificationFailed::withReason(
                'STR-Transform parameters must name exactly one canonicalization method.',
            );

        $canonicalization = SignatureCanonicalization::tryFrom((string) $method->getAttribute('Algorithm'))
            ?? throw SignatureVerificationFailed::withReason(
                'The STR-Transform canonicalization method is unknown.',
            );

        return new TransformCanonicalization(
            $canonicalization,
            $this->withDefaultNamespacePrefix(PrefixList::read($method)),
        );
    }

    public function dereference(
        Document $document,
        Element $referenced,
        Element $transform,
        IdLookup $idLookup,
    ): Element {
        // The transform describes how to read a token reference, so it says nothing about any other element.
        // A reference pointing this transform at something else is refused rather than dereferenced anyway.
        if (!ElementName::matches($referenced, WsseNamespaces::Wsse, 'SecurityTokenReference')) {
            throw SignatureVerificationFailed::withReason(
                'An STR-Transform reference must point at a wsse:SecurityTokenReference.',
            );
        }

        return $this->token($document, $referenced, $idLookup);
    }

    /**
     * @param list<string> $declared
     *
     * @return list<string>
     */
    private function withDefaultNamespacePrefix(array $declared): array
    {
        return in_array(self::DEFAULT_NAMESPACE_PREFIX, $declared, strict: true)
            ? $declared
            : [self::DEFAULT_NAMESPACE_PREFIX, ...$declared];
    }

    /**
     * The single token the reference names. Exactly one child element decides the form: a reference carrying
     * none says nothing, and one carrying several has no single answer, which a signer must not get to pick.
     */
    private function token(Document $document, Element $reference, IdLookup $idLookup): Element
    {
        $children = children($reference)->map(static fn (Element $child): Element => $child);
        if (count($children) !== 1) {
            throw SignatureVerificationFailed::withReason(
                'A wsse:SecurityTokenReference must name exactly one token.',
            );
        }

        $child = $children[0];

        if (ElementName::matches($child, WsseNamespaces::Wsse, 'Reference')) {
            return $this->byDirectReference($document, $reference, $child, $idLookup);
        }

        if (ElementName::matches($child, WsseNamespaces::Wsse, 'KeyIdentifier')) {
            return $this->bySamlKeyIdentifier($document, $child);
        }

        // ds:X509Data with an issuer and serial, wsse:Embedded, and anything else this profile does not
        // define. Each is refused for the reason the class comment gives, not silently skipped.
        throw SignatureVerificationFailed::withReason(
            'A wsse:SecurityTokenReference names the token in no form this transform reproduces.',
        );
    }

    /**
     * Resolved through the id lookup the signature's own references use, so the token is found by the same
     * hardened rule: no duplicate id, no getElementById, no DTD-declared id.
     */
    private function byDirectReference(
        Document $document,
        Element $reference,
        Element $direct,
        IdLookup $idLookup,
    ): Element {
        $id = SameDocumentId::parse((string) $direct->getAttribute('URI'))
            ?? throw SignatureVerificationFailed::withReason(
                'A token reference URI must be a non-empty same-document id.',
            );

        try {
            $resolved = $idLookup->lookup($document, $id);
        } catch (IdReferenceException $exception) {
            throw SignatureVerificationFailed::withReason(
                'The referenced security token could not be resolved.',
                $exception,
            );
        }

        // A reference resolving to a reference would let a peer put the digest one indirection further away
        // than the signature declares, and one resolving to itself is not a token at all. Neither is followed:
        // this transform dereferences exactly one hop, which is what the signature described.
        if ($resolved === $reference
            || ElementName::matches($resolved, WsseNamespaces::Wsse, 'SecurityTokenReference')
        ) {
            throw SignatureVerificationFailed::withReason(
                'A token reference must not resolve to another token reference.',
            );
        }

        return $resolved;
    }

    /**
     * A wsse:KeyIdentifier naming a SAML assertion. The ValueType states which SAML version, and the version
     * decides which attribute carries the assertion's id, so the two cannot disagree: an assertion of the
     * other version is not the token this reference described.
     *
     * The assertion is located by that attribute rather than through the injected id lookup, because a SAML
     * assertion identifies itself with ID or AssertionID and never with the wsu:Id the rest of the header
     * uses. More than one match is refused, exactly as the id lookup would.
     */
    private function bySamlKeyIdentifier(Document $document, Element $keyIdentifier): Element
    {
        $valueType = (string) $keyIdentifier->getAttribute('ValueType');
        $version = $this->samlVersionFor($valueType)
            ?? throw SignatureVerificationFailed::withReason(
                'A wsse:KeyIdentifier of this ValueType names a certificate rather than an element.',
            );

        $id = ElementText::trimmed($keyIdentifier);
        if ($id === '') {
            throw SignatureVerificationFailed::withReason('A wsse:KeyIdentifier carries no assertion id.');
        }

        $assertions = Query::elements(
            $document,
            '//saml:Assertion[@'.$version->idAttribute().'='.XPath::quote($id).']',
            prefixes: ['saml' => $version->value],
        );

        return $assertions->count() === 1
            ? $assertions->expectSingle()
            : throw SignatureVerificationFailed::withReason(
                'The referenced SAML assertion could not be resolved.',
            );
    }

    private function samlVersionFor(string $valueType): ?SamlVersion
    {
        foreach (SamlVersion::cases() as $version) {
            if ($version->keyIdentifierValueType()->value === $valueType) {
                return $version;
            }
        }

        return null;
    }
}
