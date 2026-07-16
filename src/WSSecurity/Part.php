<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;

/**
 * Describes *which* part of a message a block targets (the SOAP Body, the wsu:Timestamp, a header element by
 * QName, or an element by wsu:Id). It is a pure descriptor carrying the WS-Security shortcuts (Body,
 * Timestamp); toTarget() lowers it to the generic XmlSecurity\Target the engine resolves to a DOM node.
 */
final readonly class Part
{
    private function __construct(
        private PartKind $kind,
        private ?string $namespace = null,
        private ?string $localName = null,
        private ?string $id = null,
    ) {
    }

    public static function body(): self
    {
        return new self(PartKind::Body);
    }

    public static function timestamp(): self
    {
        return new self(PartKind::Timestamp);
    }

    /**
     * @param non-empty-string $namespace
     * @param non-empty-string $localName
     */
    public static function element(string $namespace, string $localName): self
    {
        return new self(PartKind::Element, namespace: $namespace, localName: $localName);
    }

    /**
     * @param non-empty-string $id
     */
    public static function byId(string $id): self
    {
        return new self(PartKind::Id, id: $id);
    }

    public function kind(): PartKind
    {
        return $this->kind;
    }

    public function namespace(): ?string
    {
        return $this->namespace;
    }

    public function localName(): ?string
    {
        return $this->localName;
    }

    public function id(): ?string
    {
        return $this->id;
    }

    public function equals(self $other): bool
    {
        return $this->kind === $other->kind
            && $this->namespace === $other->namespace
            && $this->localName === $other->localName
            && $this->id === $other->id;
    }

    /**
     * Lowers this Part to the generic XmlSecurity\Target the engine resolves. The SOAP shortcuts bind to their
     * concrete element: Body to soap:Body in the envelope namespace of the message's SOAP version, Timestamp to
     * wsu:Timestamp.
     */
    public function toTarget(SoapVersion $soapVersion): Target
    {
        return match ($this->kind) {
            PartKind::Body => Target::element($soapVersion->envelopeNamespace(), 'Body'),
            PartKind::Timestamp => Target::element(Namespaces::Wsu->value, 'Timestamp'),
            PartKind::Element => Target::element($this->require($this->namespace), $this->require($this->localName)),
            PartKind::Id => Target::byId($this->require($this->id)),
        };
    }

    /**
     * The Element and Id shortcuts are always built from non-empty values by element()/byId(); this restates
     * that invariant for the shared nullable storage so the Target factories keep their non-empty contract.
     *
     * @return non-empty-string
     */
    private function require(?string $value): string
    {
        assert($value !== null && $value !== '');

        return $value;
    }
}
