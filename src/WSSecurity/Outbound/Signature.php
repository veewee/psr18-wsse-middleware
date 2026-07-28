<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\IssuerSerialKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\ThumbprintKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\PartResolver;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\WsuIdLookup;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator\WsuIdMinter;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\Signer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SigningRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\XmlSigner;

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
    private bool $inclusivePrefixes = false;
    private ?CertificateChain $certificatePath = null;

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
     * Advertises the signer's whole certification path in the embedded token — a #X509PKIPathv1
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
    public function withCertificatePath(CertificateChain $path): self
    {
        if ($this->keyRef !== KeyRef::BinarySecurityToken) {
            // The inline references derive their content from the certificate alone and embed no token, so there
            // is nowhere for a path to go. Accepting it here would advertise less than the caller asked for.
            throw new InvalidArgumentException('A certificate path needs KeyRef::BinarySecurityToken to carry it.');
        }

        if ($path->leaf()->toBase64Der() !== $this->clientCertificate->publicCertificate()->toBase64Der()) {
            // The path says which key verifies this signature. One starting anywhere else advertises a key that
            // did not sign, and no receiver can verify the result.
            throw new InvalidArgumentException('A certificate path must start at the signing certificate.');
        }

        $clone = clone $this;
        $clone->certificatePath = $path;

        return $clone;
    }

    /**
     * Pins the namespace prefixes an exclusive canonicalization would otherwise drop, as an
     * ec:InclusiveNamespaces PrefixList derived per signed element. Turn this on for a peer that needs an
     * ancestor's namespace declaration to survive into the signed bytes — one that resolves a QName out of
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
     * @throws \Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException when the header cannot be created
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
            targets: (new PartResolver(new WsuIdMinter()))->resolve($parts, $document, $context->soapVersion(), $security->element()),
            signingKey: $this->clientCertificate->privateKey(),
            signingCertificate: $this->clientCertificate->publicCertificate(),
            keyIdentifier: $keyIdentifier,
            signatureMethod: $this->signatureMethod ?? $profile->crypto()->signatureMethod(),
            digestMethod: $this->digestMethod ?? $profile->crypto()->digestMethod(),
            canonicalization: $this->canonicalization ?? $profile->crypto()->canonicalization(),
            inclusivePrefixes: $this->inclusivePrefixes,
        );

        $this->signer->sign($document, $request);
    }

    private function resolveKeyIdentifier(WsseContext $context): KeyIdentifier
    {
        return match ($this->keyRef) {
            KeyRef::BinarySecurityToken => $this->binarySecurityToken()->embedAsDirectReference($context),
            KeyRef::SubjectKeyIdentifier => new X509SubjectKeyIdentifier(),
            KeyRef::IssuerSerial => new IssuerSerialKeyIdentifier(),
            KeyRef::Thumbprint => new ThumbprintKeyIdentifier(),
        };
    }

    private function binarySecurityToken(): BinarySecurityToken
    {
        return $this->certificatePath === null
            ? new BinarySecurityToken($this->clientCertificate->publicCertificate())
            : BinarySecurityToken::forCertificatePath($this->certificatePath);
    }
}
