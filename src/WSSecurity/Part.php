<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use InvalidArgumentException;

/**
 * Describes *which* part of a message a block targets (the SOAP Body, the wsu:Timestamp, a header element by
 * QName, or an element by wsu:Id). It is a pure descriptor; resolving it to a DOM node happens in the engine.
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

    public static function element(string $namespace, string $localName): self
    {
        if ($namespace === '' || $localName === '') {
            throw new InvalidArgumentException('Part::element() requires a non-empty namespace and local name.');
        }

        return new self(PartKind::Element, namespace: $namespace, localName: $localName);
    }

    public static function byId(string $id): self
    {
        if ($id === '') {
            throw new InvalidArgumentException('Part::byId() requires a non-empty id.');
        }

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
}
