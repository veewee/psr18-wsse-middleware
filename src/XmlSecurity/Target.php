<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

/**
 * A generic descriptor of the region an XML-Security operation acts on: an element addressed by qualified
 * name, or an element addressed by its id. It is a pure descriptor with no SOAP knowledge; resolving it to a
 * DOM node happens in the TargetLocator. The WS-Security profile's Part translates its SOAP shortcuts
 * (Body, Timestamp) into a Target at the boundary.
 */
final readonly class Target
{
    /**
     * @param non-empty-string|null $namespace
     * @param non-empty-string|null $localName
     * @param non-empty-string|null $id
     */
    private function __construct(
        private TargetKind $kind,
        private ?string $namespace = null,
        private ?string $localName = null,
        private ?string $id = null,
    ) {
    }

    /**
     * @param non-empty-string $namespace
     * @param non-empty-string $localName
     */
    public static function element(string $namespace, string $localName): self
    {
        return new self(TargetKind::Element, namespace: $namespace, localName: $localName);
    }

    /**
     * @param non-empty-string $id
     */
    public static function byId(string $id): self
    {
        return new self(TargetKind::Id, id: $id);
    }

    public function kind(): TargetKind
    {
        return $this->kind;
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
            && $this->id === $other->id;
    }
}
