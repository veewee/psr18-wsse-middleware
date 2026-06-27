<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Soap\Psr18WsseMiddleware\OpenSSL\CertificateFieldExtractor;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\IssuerSerialKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\ThumbprintKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\KeyHandle;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\BinaryTokenLocator;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
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
    private const VALUE_TYPE_X509V3 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';

    /** @var non-empty-list<Part>|null */
    private ?array $parts = null;

    private ?SignatureMethod $signatureMethod = null;
    private ?DigestMethod $digestMethod = null;
    private ?SignatureCanonicalization $canonicalization = null;

    private readonly XmlSigner $signer;

    public function __construct(
        private readonly ClientCertificate $clientCertificate,
        ?XmlSigner $signer = null,
        private readonly KeyRef $keyRef = KeyRef::BinarySecurityToken,
        private readonly bool $useSingleCertificate = true,
    ) {
        $this->signer = $signer ?? DefaultEngine::signer();
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
            signingKey: KeyHandle::for($this->clientCertificate->privateKey()),
            signingCertificate: $this->clientCertificate->publicCertificate(),
            keyIdentifier: $keyIdentifier,
            signatureMethod: $this->signatureMethod ?? $profile->signatureMethod(),
            digestMethod: $this->digestMethod ?? $profile->digestMethod(),
            canonicalization: $this->canonicalization ?? $profile->canonicalization(),
            useSingleCertificate: $this->useSingleCertificate,
        );

        $this->signer->sign($document, $request);
    }

    private function resolveKeyIdentifier(WsseContext $context): KeyIdentifier
    {
        return match ($this->keyRef) {
            KeyRef::BinarySecurityToken => $this->embedBinarySecurityToken($context),
            KeyRef::SubjectKeyIdentifier => new X509SubjectKeyIdentifier(new CertificateFieldExtractor()),
            KeyRef::IssuerSerial => new IssuerSerialKeyIdentifier(new CertificateFieldExtractor()),
            KeyRef::Thumbprint => new ThumbprintKeyIdentifier(new CertificateFieldExtractor()),
        };
    }

    private function embedBinarySecurityToken(WsseContext $context): DirectReferenceKeyIdentifier
    {
        $certificate = $this->clientCertificate->publicCertificate();

        $token = new BinarySecurityToken($certificate);
        $token($context);

        $id = (new BinaryTokenLocator())->locate($context->document(), $certificate);

        return new DirectReferenceKeyIdentifier($id, self::VALUE_TYPE_X509V3);
    }
}
