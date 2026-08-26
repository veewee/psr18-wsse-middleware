<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentSignatureTransform;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\IssuerSerialKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\SamlAssertionKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\ThumbprintKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SigningPartResolver;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\SamlToken;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SigningFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalParts;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\External\ExternalPartSignature;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\Signer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SigningRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\XmlSigner;

/**
 * Adds a detached, multi-reference ds:Signature to the outbound Security header. Configuration:
 *   - which key to sign with plus the advertised certificate, via ClientCertificate
 *   - which key-reference type to put in ds:KeyInfo, via KeyRef
 *   - which parts to sign (default: Body + the Security header contents; override via withParts)
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
    private bool $inclusivePrefixes = false;
    private ?CertificateChain $certificateChain = null;
    private ?KeyIdentifier $keyIdentifier = null;
    private ?ExternalParts $attachments = null;

    private XmlSigner $signer;
    private readonly SigningPartResolver $partResolver;

    public function __construct(
        private readonly ClientCertificate $clientCertificate,
        private readonly KeyRef $keyRef = KeyRef::BinarySecurityToken,
    ) {
        // The WS-Security profile mandates wsu:Id on signed parts, so the block hands the engine that
        // convention; the engine's own default (xml:id) would break the WSSE wire format. One convention serves
        // the signer and the part resolver, so nothing here can stamp one attribute and reference another.
        $convention = new WsuIdConvention();
        $this->signer = Signer::create($convention);
        $this->partResolver = new SigningPartResolver($convention->minter());
    }

    public function withSigner(XmlSigner $signer): self
    {
        $clone = clone $this;
        $clone->signer = $signer;

        return $clone;
    }

    /**
     * An empty list is refused rather than read as "the default": a signature covering nothing verifies against
     * any trusted key while protecting no part of the message, which is worse than no signature because it
     * reads as one.
     *
     * Declared as a plain list rather than a non-empty one on purpose: a static constraint is not a guard, and
     * the list a caller passes is routinely built from configuration a type checker never sees.
     *
     * @param list<Part> $parts
     *
     * @throws InvalidArgumentException when the list is empty
     */
    public function withParts(array $parts): self
    {
        if ($parts === []) {
            throw new InvalidArgumentException('A signature needs at least one part to sign.');
        }

        $clone = clone $this;
        $clone->parts = $parts;

        return $clone;
    }

    /**
     * Overrides the key reference with one built by the caller, for a ValueType this package does not model.
     * This takes a reference that is fully known before the message exists, which is what separates it from the
     * KeyRef cases: those resolve against the message in flight. It wins over the keyRef passed at construction.
     */
    public function withKeyIdentifier(KeyIdentifier $keyIdentifier): self
    {
        $clone = clone $this;
        $clone->keyIdentifier = $keyIdentifier;

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
     * Advertises the signer's whole certification path in the embedded token. A #X509PKIPathv1
     * wsse:BinarySecurityToken instead of the leaf certificate alone. Turn this on for a peer that will not
     * complete the chain from its own store and needs the intermediates handed to it; leave it off otherwise,
     * because a bare certificate is what every stack accepts without configuration.
     *
     * The path is supplied here rather than carried on the signing identity: a PKCS#12 bundle already holds one
     * ($bundle->chain), a PEM signing identity has none to offer, and no peer requires a path, so the capability
     * belongs where it is asked for.
     *
     * @throws InvalidArgumentException when no token is embedded to carry the path, or when the path does not
     *         start at the signing certificate
     */
    public function withCertificatePath(CertificateChain $chain): self
    {
        if ($this->keyRef !== KeyRef::BinarySecurityToken) {
            // The inline references derive their content from the certificate alone and embed no token, so there
            // is nowhere for a path to go. Accepting it here would advertise less than the caller asked for.
            throw new InvalidArgumentException('A certificate path needs KeyRef::BinarySecurityToken to carry it.');
        }

        if ($chain->leaf()->toBase64Der() !== $this->clientCertificate->publicCertificate()->toBase64Der()) {
            // The path says which key verifies this signature. One starting anywhere else advertises a key that
            // did not sign, and no receiver can verify the result.
            throw new InvalidArgumentException('A certificate path must start at the signing certificate.');
        }

        $clone = clone $this;
        $clone->certificateChain = $chain;

        return $clone;
    }

    /**
     * Pins the namespace prefixes an exclusive canonicalization would otherwise drop, as an
     * ec:InclusiveNamespaces PrefixList derived per signed element. Turn this on for a peer that needs an
     * ancestor's namespace declaration to survive into the signed bytes: one that resolves a QName out of
     * attribute or text content, or re-serializes the message before verifying. It is off by default because
     * emitting the narrowest possible declaration set is what lets a signature move between envelopes.
     */
    public function withInclusivePrefixes(): self
    {
        $clone = clone $this;
        $clone->inclusivePrefixes = true;

        return $clone;
    }

    /**
     * Covers the message's attachments as well as its in-document parts, in the same ds:Signature.
     *
     * The parts are read when the message is signed, not now, because they belong to the call in flight.
     * Registering them adds coverage and never replaces what withParts() asks for: an attachment reference
     * sits alongside the Body's, which is the shape a peer's sp:SignedParts policy is checked against.
     *
     * Pass AttachmentParts::request() for the outbound side. Only this block and its inbound twin know that
     * these are attachments at all: the engine is handed the profile's transform URI and a list of parts.
     */
    public function withAttachments(ExternalParts $attachments): self
    {
        $clone = clone $this;
        $clone->attachments = $attachments;

        return $clone;
    }

    /**
     * @throws \Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException when the header cannot be created
     * @throws \Soap\Psr18WsseMiddleware\XmlSecurity\Exception\IdStampFailed when a signed part cannot carry a wsu:Id
     * @throws \Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SigningFailed when signing fails
     */
    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();
        $profile = $context->profile();

        $security = SecurityHeader::forContext($context);

        $keyIdentifier = $this->resolveKeyIdentifier($context);

        $parts = $this->parts ?? [Part::body(), Part::securityHeaderContents()];
        $request = new SigningRequest(
            container: $security->element(),
            targets: $this->partResolver->resolve($parts, $document, $context->soapVersion(), $security->element()),
            signingKey: $this->clientCertificate->privateKey(),
            signingCertificate: $this->clientCertificate->publicCertificate(),
            keyIdentifier: $keyIdentifier,
            signatureMethod: $this->signatureMethod ?? $profile->crypto()->signatureMethod(),
            digestMethod: $this->digestMethod ?? $profile->crypto()->digestMethod(),
            canonicalization: $this->canonicalization ?? $profile->crypto()->canonicalization(),
            inclusivePrefixes: $this->inclusivePrefixes,
            externalParts: $this->externalPartSignature(),
        );

        $signed = $this->signer->sign($document, $request);
        $this->assertEveryRegisteredPartCovered($request->externalParts?->parts, $signed->covered);

        // The engine appends the signature; which order this header must be in is the profile's rule.
        $security->sort();
    }

    /**
     * Every part handed to the signer must come back named as covered.
     *
     * The signer reports its coverage instead of the block trusting the request it sent, because the signer
     * is a seam a caller may replace. One that returns a signature over less than it was asked for would
     * otherwise leave an attachment travelling unsigned while the caller believes the opposite, which is a
     * failure with nothing on this side to notice it.
     *
     * @throws SigningFailed
     */
    private function assertEveryRegisteredPartCovered(
        ?ExternalPartList $registeredAttachments,
        ExternalPartList $covered,
    ): void {
        foreach ($registeredAttachments ?? ExternalPartList::of() as $part) {
            if ($covered->byReference($part->reference) === null) {
                throw SigningFailed::uncoveredExternalPart($part->reference);
            }
        }
    }

    /**
     * The SwA content transform is this block's to declare, exactly as it owns lowering a Part into a Target.
     * The engine is told which transform a reference declares and never learns that it names an attachment.
     *
     * The parts are collected here rather than at wiring time because the storage holds the message in
     * flight. Sign-then-encrypt collects the same message twice, once here and once in the encryption block,
     * which is why the seam promises rewound streams.
     */
    private function externalPartSignature(): ?ExternalPartSignature
    {
        $attachments = $this->attachments;
        if ($attachments === null) {
            return null;
        }

        return new ExternalPartSignature(
            $attachments->collect(),
            AttachmentSignatureTransform::for($attachments->coverage())->value,
        );
    }

    private function resolveKeyIdentifier(WsseContext $context): KeyIdentifier
    {
        if ($this->keyIdentifier !== null) {
            return $this->keyIdentifier;
        }

        return match ($this->keyRef) {
            KeyRef::BinarySecurityToken => $this->binarySecurityToken()->embedAsDirectReference($context),
            KeyRef::SubjectKeyIdentifier => new X509SubjectKeyIdentifier(),
            KeyRef::IssuerSerial => new IssuerSerialKeyIdentifier(),
            KeyRef::Thumbprint => new ThumbprintKeyIdentifier(),
            KeyRef::SamlAssertion => $this->samlAssertionReference($context),
        };
    }

    /**
     * The Holder-of-Key reference: the signature names the assertion that vouches for the signing key, so the
     * receiver resolves the key through the assertion rather than from a certificate the message carries.
     *
     * The assertion is found in the Security header, the same way the direct-reference path finds the token it
     * embedded. Nothing is carried between the two blocks: an Outbound\SamlAssertion earlier in the list has
     * already put the assertion there, and its id and version are read off the element itself.
     *
     * @throws \Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException when the header carries no
     *                                                                            assertion, or more than one
     */
    private function samlAssertionReference(WsseContext $context): SamlAssertionKeyIdentifier
    {
        $assertion = (new SamlToken())->locate(SecurityHeader::forContext($context)->element());

        return new SamlAssertionKeyIdentifier($assertion->id, $assertion->version);
    }

    private function binarySecurityToken(): BinarySecurityToken
    {
        return $this->certificateChain === null
            ? new BinarySecurityToken($this->clientCertificate->publicCertificate())
            : BinarySecurityToken::forCertificatePath($this->certificateChain);
    }
}
