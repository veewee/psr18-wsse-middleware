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
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Request\SigningRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\XmlSigner;

/**
 * Adds a detached, multi-reference ds:Signature to the outbound Security header. Configuration:
 *   - which key to sign with plus the advertised certificate, via ClientCertificate
 *   - which key-reference type to put in ds:KeyInfo, via KeyRef
 *   - which parts to sign (default: Body + Timestamp; override via withParts)
 *   - algorithms (default: the injected profile, falling back to the secure default; override per block)
 *
 * For the direct-reference path (KeyRef::binarySecurityToken()), the block embeds a
 * wsse:BinarySecurityToken before signing, reads its minted wsu:Id, and points a
 * DirectReferenceKeyIdentifier at it. For the inline key-reference types (SKI / IssuerSerial /
 * Thumbprint) no token is embedded; the strategy derives its content from the certificate alone.
 *
 * The Security header is guaranteed to exist before the signer runs. Algorithm resolution order:
 * per-block override, then the injected profile, then the secure default.
 */
final class Signature implements OutboundAction
{
    private const VALUE_TYPE_X509V3 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';

    private readonly SecurityProfile $profile;
    private readonly KeyRef $keyRef;

    /** @var non-empty-list<Part>|null */
    private ?array $parts = null;

    private ?SignatureMethod $signatureMethod = null;
    private ?DigestMethod $digestMethod = null;
    private ?SignatureCanonicalization $canonicalization = null;

    public function __construct(
        private readonly XmlSigner $signer,
        private readonly ClientCertificate $clientCertificate,
        ?SecurityProfile $profile = null,
        ?KeyRef $keyRef = null,
        private readonly bool $useSingleCertificate = true,
    ) {
        $this->profile = $profile ?? SecurityProfile::default();
        $this->keyRef = $keyRef ?? KeyRef::binarySecurityToken();
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

        $request = new SigningRequest(
            parts: $this->parts ?? [Part::body(), Part::timestamp()],
            signingKey: KeyHandle::for($this->clientCertificate->privateKey()),
            signingCertificate: $this->clientCertificate->publicCertificate(),
            keyIdentifier: $keyIdentifier,
            signatureMethod: $this->signatureMethod ?? $this->profile->signatureMethod(),
            digestMethod: $this->digestMethod ?? $this->profile->digestMethod(),
            canonicalization: $this->canonicalization ?? $this->profile->canonicalization(),
            useSingleCertificate: $this->useSingleCertificate,
        );

        $this->signer->sign($document, $request);
    }

    private function resolveKeyIdentifier(WsseContext $context): KeyIdentifier
    {
        return match ($this->keyRef->kind()) {
            KeyRefKind::DirectReference => $this->embedBinarySecurityToken($context),
            KeyRefKind::SubjectKeyIdentifier => new X509SubjectKeyIdentifier(new CertificateFieldExtractor()),
            KeyRefKind::IssuerSerial => new IssuerSerialKeyIdentifier(new CertificateFieldExtractor()),
            KeyRefKind::Thumbprint => new ThumbprintKeyIdentifier(new CertificateFieldExtractor()),
        };
    }

    private function embedBinarySecurityToken(WsseContext $context): DirectReferenceKeyIdentifier
    {
        $token = new BinarySecurityToken($this->clientCertificate->publicCertificate());
        $token($context);

        return new DirectReferenceKeyIdentifier($token->mintedId(), self::VALUE_TYPE_X509V3);
    }
}
