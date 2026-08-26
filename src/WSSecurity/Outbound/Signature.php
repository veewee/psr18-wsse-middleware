<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentSignatureTransform;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SigningPartResolver;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
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
 *   - how the signature is keyed and referenced, via a SigningKey: a CertificateSigningKey for the X.509 forms,
 *     a SymmetricSigningKey for a MAC keyed off a shared session key
 *   - which parts to sign (default: Body + the Security header contents; override via withParts)
 *   - algorithms (default: the profile carried on the context; override per block)
 *
 * The signing key is asked for a key only once the signature method is known, because the method decides what
 * kind of key the signature needs and how much of it. A mismatch between the two is refused there rather than
 * producing a signature keyed by the wrong thing.
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
    private ?KeyIdentifier $keyIdentifier = null;
    private ?ExternalParts $attachments = null;

    private XmlSigner $signer;
    private readonly SigningPartResolver $partResolver;

    public function __construct(
        private readonly SigningKey $signingKey,
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
     * references a SigningKey resolves: those are built against the message in flight. It wins over whatever the
     * signing key resolved, and is orthogonal to where the key itself came from.
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

        $signatureMethod = $this->signatureMethod ?? $profile->crypto()->signatureMethod();
        $key = $this->signingKey->resolve($context, $signatureMethod);

        $parts = $this->parts ?? [Part::body(), Part::securityHeaderContents()];
        $request = new SigningRequest(
            container: $security->element(),
            targets: $this->partResolver->resolve($parts, $document, $context->soapVersion(), $security->element()),
            signingKey: $key->key,
            keyIdentifier: $this->keyIdentifier ?? $key->keyIdentifier,
            signatureMethod: $signatureMethod,
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
}
