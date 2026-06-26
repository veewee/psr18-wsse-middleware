<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Soap\Psr18WsseMiddleware\OpenSSL\CertificateFieldExtractor;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\IssuerSerialKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\ThumbprintKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\KeyHandle;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Request\EncryptionRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\XmlEncryptor;

/**
 * Encrypts the requested parts of the outbound message via XML-Enc. Configuration:
 *   - the recipient public certificate, used to wrap the session key
 *   - which key-reference type to put in xenc:EncryptedKey/ds:KeyInfo, via EncKeyRef
 *   - which parts to encrypt (default: Body only; override via withParts)
 *   - algorithms (default: the injected profile, falling back to the secure default; override per block)
 *
 * For the direct-reference path (EncKeyRef::binarySecurityToken()), the block embeds a
 * wsse:BinarySecurityToken before encrypting, reads its minted wsu:Id, and points a
 * DirectReferenceKeyIdentifier at it. For the inline key-reference types (SKI / IssuerSerial /
 * Thumbprint) no token is embedded; the strategy derives its content from the recipient certificate alone.
 *
 * The Security header is guaranteed to exist before the encryptor runs. Algorithm resolution order:
 * per-block override, then the injected profile, then the secure default.
 *
 * Intended position in the outbound list: after Outbound\Signature (sign-then-encrypt). The engine
 * places xenc:EncryptedKey before ds:Signature in the Security header; this block takes no action on it.
 */
final class Encryption implements OutboundAction
{
    private const VALUE_TYPE_X509V3 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';

    private readonly SecurityProfile $profile;
    private readonly EncKeyRef $encKeyRef;

    /** @var non-empty-list<Part>|null */
    private ?array $parts = null;

    private ?DataEncryptionMethod $dataEncryptionMethod = null;
    private ?KeyEncryptionMethod $keyEncryptionMethod = null;

    public function __construct(
        private readonly XmlEncryptor $encryptor,
        private readonly Certificate $recipientCertificate,
        ?SecurityProfile $profile = null,
        ?EncKeyRef $encKeyRef = null,
    ) {
        $this->profile = $profile ?? SecurityProfile::default();
        $this->encKeyRef = $encKeyRef ?? EncKeyRef::subjectKeyIdentifier();
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

    public function withDataEncryptionMethod(DataEncryptionMethod $method): self
    {
        $clone = clone $this;
        $clone->dataEncryptionMethod = $method;

        return $clone;
    }

    public function withKeyEncryptionMethod(KeyEncryptionMethod $method): self
    {
        $clone = clone $this;
        $clone->keyEncryptionMethod = $method;

        return $clone;
    }

    /**
     * @throws \Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException when the header cannot be created
     * @throws \Soap\Psr18WsseMiddleware\WSSecurity\Exception\EncryptionFailed when encryption fails
     */
    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();

        SecurityHeader::locateOrCreate($document, $context->soapVersion());

        $keyIdentifier = $this->resolveKeyIdentifier($context);

        $request = new EncryptionRequest(
            parts: $this->parts ?? [Part::body()],
            recipientCertificate: KeyHandle::for($this->recipientCertificate),
            keyIdentifier: $keyIdentifier,
            dataEncryptionMethod: $this->dataEncryptionMethod ?? $this->profile->dataEncryptionMethod(),
            keyEncryptionMethod: $this->keyEncryptionMethod ?? $this->profile->keyEncryptionMethod(),
        );

        $this->encryptor->encrypt($document, $request);
    }

    private function resolveKeyIdentifier(WsseContext $context): KeyIdentifier
    {
        return match ($this->encKeyRef->kind()) {
            EncKeyRefKind::SubjectKeyIdentifier => new X509SubjectKeyIdentifier(new CertificateFieldExtractor()),
            EncKeyRefKind::IssuerSerial => new IssuerSerialKeyIdentifier(new CertificateFieldExtractor()),
            EncKeyRefKind::Thumbprint => new ThumbprintKeyIdentifier(new CertificateFieldExtractor()),
            EncKeyRefKind::DirectReference => $this->embedBinarySecurityToken($context),
        };
    }

    private function embedBinarySecurityToken(WsseContext $context): DirectReferenceKeyIdentifier
    {
        $token = new BinarySecurityToken($this->recipientCertificate);
        $token($context);

        return new DirectReferenceKeyIdentifier($token->mintedId(), self::VALUE_TYPE_X509V3);
    }
}
