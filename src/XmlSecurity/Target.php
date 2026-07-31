<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Soap\Psr18WsseMiddleware\Xml\QualifiedName;

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
     * @param list<QualifiedName>   $steps
     */
    private function __construct(
        private TargetKind $kind,
        private ?string $namespace = null,
        private ?string $localName = null,
        private ?string $id = null,
        private array $steps = [],
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

    /**
     * The element at a position rather than the element with a name: the steps are walked from the document
     * element down, and each must match exactly one direct child of the one before it. The first step names the
     * document element itself, so the path also states which document shape it belongs to.
     *
     * Addressing by name alone is satisfied by that name wherever it sits, which lets a signed element be moved
     * out of the place a reader will look while still answering for it.
     */
    public static function path(QualifiedName ...$steps): self
    {
        return new self(TargetKind::Path, steps: array_values($steps));
    }

    public function kind(): TargetKind
    {
        return $this->kind;
    }

    /**
     * @return list<QualifiedName>
     */
    public function steps(): array
    {
        return $this->steps;
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
            && $this->sameSteps($other);
    }

    private function sameSteps(self $other): bool
    {
        if (count($this->steps) !== count($other->steps)) {
            return false;
        }

        foreach ($this->steps as $index => $step) {
            if (!$step->equals($other->steps[$index])) {
                return false;
            }
        }

        return true;
    }
}
