<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use InvalidArgumentException;
use LogicException;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncKeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\IssuerSerialKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\ThumbprintKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionTarget;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\Encryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlEncryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;

/**
 * Encrypts the requested parts of the outbound message via XML-Enc. Configuration:
 *   - the recipient public certificate, used to wrap the session key
 *   - which key-reference type to put in xenc:EncryptedKey/ds:KeyInfo, via EncKeyRef
 *   - which parts to encrypt (default: Body only; override via withParts)
 *   - algorithms (default: the profile carried on the context; override per block)
 *
 * For the direct-reference path (EncKeyRef::BinarySecurityToken), the block embeds a
 * wsse:BinarySecurityToken before encrypting, locates it by content in the Security header to read its
 * wsu:Id, and points a DirectReferenceKeyIdentifier at it. For the inline key-reference types (SKI / IssuerSerial /
 * Thumbprint) no token is embedded; the strategy derives its content from the recipient certificate alone.
 *
 * The Security header is guaranteed to exist before the encryptor runs. Algorithm resolution order:
 * per-block override, then the profile carried on the context.
 *
 * Intended position in the outbound list: after Outbound\Signature (sign-then-encrypt). The engine
 * places xenc:EncryptedKey before ds:Signature in the Security header; this block takes no action on it.
 */
final class Encryption implements OutboundAction
{
    /** @var non-empty-list<Part>|null */
    private ?array $parts = null;

    private ?DataEncryptionMethod $dataEncryptionMethod = null;
    private ?KeyEncryptionMethod $keyEncryptionMethod = null;
    private ?KeyTransportAlgorithm $keyTransportAlgorithm = null;

    private XmlEncryptor $encryptor;

    public function __construct(
        private readonly Certificate $recipientCertificate,
        private readonly EncKeyRef $encKeyRef = EncKeyRef::SubjectKeyIdentifier,
    ) {
        // The WS-Security profile mandates wsu:Id on the xenc:EncryptedData, so the block injects the wsu:Id
        // convention on both sides. The engine's own default (xml:id) would break the WSSE wire format.
        $this->encryptor = Encryptor::create(new WsuIdConvention());
    }

    public function withEncryptor(XmlEncryptor $encryptor): self
    {
        $clone = clone $this;
        $clone->encryptor = $encryptor;

        return $clone;
    }

    /**
     * An empty list is refused rather than read as "the default": encrypting nothing still wraps a session key
     * and appends an xenc:EncryptedKey, so the Body would leave in cleartext under a message that reads as
     * encrypted everywhere it is logged or captured.
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
            throw new InvalidArgumentException('Encryption needs at least one part to encrypt.');
        }

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

    /**
     * Overrides only the key-encryption method; the OAEP hash is resolved from the profile (or its default) at
     * apply time. For a method paired with a specific hash, use withKeyTransportAlgorithm.
     */
    public function withKeyEncryptionMethod(KeyEncryptionMethod $method): self
    {
        $clone = clone $this;
        $clone->keyEncryptionMethod = $method;

        return $clone;
    }

    /**
     * Overrides the whole key-transport choice atomically: an invalid method/hash pairing cannot be expressed,
     * and this override wins over withKeyEncryptionMethod and the profile.
     */
    public function withKeyTransportAlgorithm(KeyTransportAlgorithm $algorithm): self
    {
        $clone = clone $this;
        $clone->keyTransportAlgorithm = $algorithm;

        return $clone;
    }

    /**
     * @throws \Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException when the header cannot be created
     * @throws \Soap\Psr18WsseMiddleware\XmlSecurity\Exception\IdStampFailed when an encrypted part cannot carry a wsu:Id
     * @throws \Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed when encryption fails
     */
    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();

        $security = SecurityHeader::forContext($context);

        $keyIdentifier = $this->resolveKeyIdentifier($context);
        $profile = $context->profile();

        $keyTransportAlgorithm = $this->keyTransportAlgorithm ?? KeyTransportAlgorithm::fromMethod(
            $this->keyEncryptionMethod ?? $profile->crypto()->keyEncryptionMethod(),
            $profile->crypto()->oaepHash(),
        );

        $parts = $this->parts ?? [Part::body()];
        $soapVersion = $context->soapVersion();
        $request = new EncryptionRequest(
            container: $security->element(),
            targets: array_map(
                static fn (Part $part): EncryptionTarget => new EncryptionTarget(
                    $part->toTarget($soapVersion),
                    // A null mode marks a signing-only part (securityHeaderContents/soapHeaders): not encryptable.
                    $part->encryptionMode() ?? throw new LogicException(
                        'A signing-only Part (securityHeaderContents/soapHeaders) cannot be encrypted.',
                    ),
                ),
                $parts,
            ),
            recipientCertificate: $this->recipientCertificate,
            keyIdentifier: $keyIdentifier,
            dataEncryptionMethod: $this->dataEncryptionMethod ?? $profile->crypto()->dataEncryptionMethod(),
            keyTransportAlgorithm: $keyTransportAlgorithm,
        );

        $this->encryptor->encrypt($document, $request);

        // The engine appends the encrypted key; which order this header must be in is the profile's rule.
        $security->sort();
    }

    private function resolveKeyIdentifier(WsseContext $context): KeyIdentifier
    {
        return match ($this->encKeyRef) {
            EncKeyRef::SubjectKeyIdentifier => new X509SubjectKeyIdentifier(),
            EncKeyRef::IssuerSerial => new IssuerSerialKeyIdentifier(),
            EncKeyRef::Thumbprint => new ThumbprintKeyIdentifier(),
            EncKeyRef::BinarySecurityToken => (new BinarySecurityToken($this->recipientCertificate))
                ->embedAsDirectReference($context),
        };
    }
}
