<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use LogicException;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionMode;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;

/**
 * Describes *which* part of a message a block targets (the SOAP Body, the wsu:Timestamp, a header element by
 * QName, or an element by wsu:Id). It is a pure descriptor carrying the WS-Security shortcuts (Body,
 * Timestamp); toTarget() lowers it to the generic XmlSecurity\Target the engine resolves to a DOM node.
 *
 * The encryption mode says how the part is encrypted (Content keeps the element wrapper, Element replaces it
 * whole); it is null for signing-only parts, which the Encryption block rejects. Signing ignores it.
 */
final readonly class Part
{
    /**
     * @param non-empty-string|null $namespace
     * @param non-empty-string|null $localName
     * @param non-empty-string|null $id
     */
    private function __construct(
        private PartKind $kind,
        private ?string $namespace = null,
        private ?string $localName = null,
        private ?string $id = null,
        private ?EncryptionMode $encryptionMode = null,
    ) {
    }

    public static function body(): self
    {
        return new self(PartKind::Body, encryptionMode: EncryptionMode::Content);
    }

    /**
     * The wsu:Timestamp in the Security header (shortcut for element() with the WS-Security utility namespace).
     */
    public static function timestamp(): self
    {
        return self::element(Namespaces::Wsu->value, 'Timestamp');
    }

    /**
     * The wsse:UsernameToken in the Security header (shortcut for element() with the WS-Security namespace).
     */
    public static function usernameToken(): self
    {
        return self::element(Namespaces::Wsse->value, 'UsernameToken');
    }

    /**
     * The wsse:BinarySecurityToken in the Security header (shortcut for element() with the WS-Security
     * namespace); signing it binds the carried certificate to the signature.
     */
    public static function binarySecurityToken(): self
    {
        return self::element(Namespaces::Wsse->value, 'BinarySecurityToken');
    }

    /**
     * Every current child of the wsse:Security header (Timestamp, tokens, ...). A dynamic part expanded against
     * the live message: the Signature block signs each element it finds, VerifySignature can require each was
     * signed. It targets whatever is present, so it never fails for an absent element the way naming one part
     * explicitly would. The migration equivalent of wse-php signing the Security-header children.
     */
    public static function securityHeaderContents(): self
    {
        return new self(PartKind::SecurityHeaderContents);
    }

    /**
     * Every current SOAP header block except the wsse:Security header itself (for example WS-Addressing
     * headers). A dynamic part expanded against the live message (signed outbound, required inbound); the
     * migration equivalent of wse-php's signAllHeaders.
     */
    public static function soapHeaders(): self
    {
        return new self(PartKind::SoapHeaders);
    }

    /**
     * @param non-empty-string $namespace
     * @param non-empty-string $localName
     */
    public static function element(string $namespace, string $localName): self
    {
        return new self(PartKind::Element, namespace: $namespace, localName: $localName, encryptionMode: EncryptionMode::Element);
    }

    /**
     * @param non-empty-string $id
     */
    public static function byId(string $id): self
    {
        return new self(PartKind::Id, id: $id, encryptionMode: EncryptionMode::Element);
    }

    /**
     * Overrides how this part is encrypted (Content keeps the element wrapper, Element replaces it whole).
     */
    public function withEncryptionMode(EncryptionMode $mode): self
    {
        return new self($this->kind, $this->namespace, $this->localName, $this->id, $mode);
    }

    public function kind(): PartKind
    {
        return $this->kind;
    }

    /**
     * How this part is encrypted, or null when it is signing-only and cannot be encrypted.
     */
    public function encryptionMode(): ?EncryptionMode
    {
        return $this->encryptionMode;
    }

    /**
     * @return non-empty-string|null
     */
    public function namespace(): ?string
    {
        return $this->namespace;
    }

    /**
     * @return non-empty-string|null
     */
    public function localName(): ?string
    {
        return $this->localName;
    }

    /**
     * @return non-empty-string|null
     */
    public function id(): ?string
    {
        return $this->id;
    }

    public function equals(self $other): bool
    {
        return $this->kind === $other->kind
            && $this->namespace === $other->namespace
            && $this->localName === $other->localName
            && $this->id === $other->id
            && $this->encryptionMode === $other->encryptionMode;
    }

    /**
     * Lowers this Part to the generic XmlSecurity\Target the engine resolves. The SOAP shortcuts bind to their
     * concrete element: Body to soap:Body in the envelope namespace of the message's SOAP version, Timestamp to
     * wsu:Timestamp. The dynamic parts have no single Target; the Signature block expands them against the live
     * document instead, so lowering one here is a programming error.
     *
     * @throws LogicException when called on a dynamic part (securityHeaderContents/soapHeaders)
     */
    public function toTarget(SoapVersion $soapVersion): Target
    {
        return match ($this->kind) {
            PartKind::Body => Target::element($soapVersion->envelopeNamespace(), 'Body'),
            PartKind::Element => Target::element($this->require($this->namespace), $this->require($this->localName)),
            PartKind::Id => Target::byId($this->require($this->id)),
            PartKind::SecurityHeaderContents, PartKind::SoapHeaders => throw new LogicException(
                'A dynamic Part (securityHeaderContents/soapHeaders) is expanded by the Signature block against '
                .'the live document; it does not lower to a single Target.',
            ),
        };
    }

    /**
     * Reads a field the current kind guarantees is set. The storage is nullable because it is shared across
     * every kind, so the Element and Id arms have to restate which fields their own factories populated.
     *
     * @param non-empty-string|null $value
     *
     * @return non-empty-string
     */
    private function require(?string $value): string
    {
        return $value ?? throw new LogicException('A Part field its own kind guarantees was not set.');
    }
}
