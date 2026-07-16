<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\IssuerSerialKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\ThumbprintKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityValueType;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\DefaultEngine;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\SigningRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\XmlSigner;

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
        $this->signer = DefaultEngine::signer();
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
     * @throws \Soap\Psr18WsseMiddleware\WSSecurity\Exception\SigningFailed when signing fails
     */
    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();

        SecurityHeader::locateOrCreate($document, $context->soapVersion(), mustUnderstand: true);

        $keyIdentifier = $this->resolveKeyIdentifier($context);
        $profile = $context->profile();

        $request = new SigningRequest(
            parts: $this->parts ?? [Part::body(), Part::timestamp()],
            signingKey: $this->clientCertificate->privateKey(),
            signingCertificate: $this->clientCertificate->publicCertificate(),
            keyIdentifier: $keyIdentifier,
            signatureMethod: $this->signatureMethod ?? $profile->signatureMethod(),
            digestMethod: $this->digestMethod ?? $profile->digestMethod(),
            canonicalization: $this->canonicalization ?? $profile->canonicalization(),
        );

        $this->signer->sign($document, $request);
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
