<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\IssuerSerialKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\ThumbprintKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\PartKind;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\WsuIdLookup;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator\WsuIdMinter;
use Soap\Psr18WsseMiddleware\Xml\Query;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\Signer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SigningRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\XmlSigner;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use Soap\Psr18WsseMiddleware\XmlSecurity\WsSecurityValueType;
use VeeWee\Xml\Dom\Document;

/**
 * Adds a detached, multi-reference ds:Signature to the outbound Security header. Configuration:
 *   - which key to sign with plus the advertised certificate, via ClientCertificate
 *   - which key-reference type to put in ds:KeyInfo, via KeyRef
 *   - which parts to sign (default: Body + Timestamp; override via withParts)
 *   - algorithms (default: the profile carried on the context; override per block)
 *
 * For the direct-reference path (KeyRef::BinarySecurityToken), the block embeds a
 * wsse:BinarySecurityToken before signing, locates it by content in the Security header to read its
 * wsu:Id, and points a DirectReferenceKeyIdentifier at it. For the inline key-reference types (SKI / IssuerSerial /
 * Thumbprint) no token is embedded; the strategy derives its content from the certificate alone.
 *
 * The Security header is guaranteed to exist before the signer runs. Algorithm resolution order:
 * per-block override, then the profile carried on the context.
 */
final class Signature implements OutboundAction
{
    /** @var non-empty-list<Part>|null */
    private ?array $parts = null;

    private ?SignatureMethod $signatureMethod = null;
    private ?DigestMethod $digestMethod = null;
    private ?SignatureCanonicalization $canonicalization = null;

    private XmlSigner $signer;

    public function __construct(
        private readonly ClientCertificate $clientCertificate,
        private readonly KeyRef $keyRef = KeyRef::BinarySecurityToken,
    ) {
        // The WS-Security profile mandates wsu:Id on signed parts, so the block injects the wsu:Id convention on
        // both sides — the minter stamps it, the paired lookup re-finds it on the reparsed wire. The engine's
        // own default (xml:id) would break the WSSE wire format.
        $this->signer = Signer::create(new WsuIdMinter(), new WsuIdLookup());
    }

    public function withSigner(XmlSigner $signer): self
    {
        $clone = clone $this;
        $clone->signer = $signer;

        return $clone;
    }

    /**
     * @param non-empty-list<Part> $parts
     */
    public function withParts(array $parts): self
    {
        $clone = clone $this;
        $clone->parts = $parts;

        return $clone;
    }

    public function withSignatureMethod(SignatureMethod $method): self
    {
        $clone = clone $this;
        $clone->signatureMethod = $method;

        return $clone;
    }

    public function withDigestMethod(DigestMethod $method): self
    {
        $clone = clone $this;
        $clone->digestMethod = $method;

        return $clone;
    }

    public function withCanonicalization(SignatureCanonicalization $canonicalization): self
    {
        $clone = clone $this;
        $clone->canonicalization = $canonicalization;

        return $clone;
    }

    /**
     * @throws \Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException when the header cannot be created
     * @throws \Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SigningFailed when signing fails
     */
    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();

        $security = SecurityHeader::locateOrCreate($document, $context->soapVersion(), mustUnderstand: true);

        $keyIdentifier = $this->resolveKeyIdentifier($context);
        $profile = $context->profile();

        $parts = $this->parts ?? [Part::body(), Part::securityHeaderContents()];
        $request = new SigningRequest(
            container: $security->element(),
            targets: $this->resolveTargets($parts, $context->soapVersion(), $security->element(), $document),
            signingKey: $this->clientCertificate->privateKey(),
            signingCertificate: $this->clientCertificate->publicCertificate(),
            keyIdentifier: $keyIdentifier,
            signatureMethod: $this->signatureMethod ?? $profile->crypto()->signatureMethod(),
            digestMethod: $this->digestMethod ?? $profile->crypto()->digestMethod(),
            canonicalization: $this->canonicalization ?? $profile->crypto()->canonicalization(),
        );

        $this->signer->sign($document, $request);
    }

    /**
     * Lowers the configured parts to engine Targets. Static parts lower directly; the dynamic parts
     * (securityHeaderContents, soapHeaders) are expanded against the live header, stamping a wsu:Id on each
     * matched element (idempotent: an id an earlier block already minted is reused) and targeting it by that id.
     *
     * @param non-empty-list<Part> $parts
     *
     * @return non-empty-list<Target>
     *
     * @throws WsseHeaderException when the parts match no element to sign
     */
    private function resolveTargets(array $parts, SoapVersion $soapVersion, Element $securityHeader, Document $document): array
    {
        $minter = new WsuIdMinter();
        $targets = [];
        foreach ($parts as $part) {
            $dynamic = $this->dynamicMembers($part, $securityHeader, $document);
            if ($dynamic !== null) {
                foreach ($dynamic as $element) {
                    $targets[] = Target::byId($minter->mint($element, $document));
                }

                continue;
            }

            $targets[] = $part->toTarget($soapVersion);
        }

        if ($targets === []) {
            throw WsseHeaderException::nothingToSign();
        }

        return $targets;
    }

    /**
     * The elements a dynamic part expands to, or null when the part is not dynamic. SecurityHeaderContents is
     * every child of the Security header; SoapHeaders is every SOAP header block except the Security header
     * itself.
     *
     * @return list<Element>|null
     */
    private function dynamicMembers(Part $part, Element $securityHeader, Document $document): ?array
    {
        return match ($part->kind()) {
            PartKind::SecurityHeaderContents => $this->childElements($document, $securityHeader),
            PartKind::SoapHeaders => array_values(array_filter(
                $this->childElements($document, $this->soapHeader($securityHeader)),
                static fn (Element $header): bool => $header !== $securityHeader,
            )),
            default => null,
        };
    }

    /**
     * The SOAP Header element carrying the Security header (always its parent element).
     */
    private function soapHeader(Element $securityHeader): Element
    {
        $header = $securityHeader->parentElement;
        assert($header instanceof Element);

        return $header;
    }

    /**
     * @return list<Element>
     */
    private function childElements(Document $document, Element $element): array
    {
        return Query::elements($document, 'child::*', $element)
            ->map(static fn (Element $child): Element => $child);
    }

    private function resolveKeyIdentifier(WsseContext $context): KeyIdentifier
    {
        return match ($this->keyRef) {
            KeyRef::BinarySecurityToken => $this->embedBinarySecurityToken($context),
            KeyRef::SubjectKeyIdentifier => new X509SubjectKeyIdentifier(),
            KeyRef::IssuerSerial => new IssuerSerialKeyIdentifier(),
            KeyRef::Thumbprint => new ThumbprintKeyIdentifier(),
        };
    }

    private function embedBinarySecurityToken(WsseContext $context): DirectReferenceKeyIdentifier
    {
        $certificate = $this->clientCertificate->publicCertificate();
        $id = (new BinarySecurityToken($certificate))->embed($context);

        return new DirectReferenceKeyIdentifier($id, WsSecurityValueType::X509v3->value);
    }
}
