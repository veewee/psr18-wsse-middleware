<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

use Dom\Element;

/**
 * A namespace URI paired with a local name: the two halves that identify an element, held together so neither
 * can be passed without the other.
 *
 * The comparison rule itself is not restated here. It defers to ElementName, so an unqualified element, or one
 * in a look-alike namespace, can never stand in for the element a reader expects.
 */
final readonly class QualifiedName
{
    /**
     * @param non-empty-string $namespace
     * @param non-empty-string $localName
     */
    public function __construct(
        public string $namespace,
        public string $localName,
    ) {
    }

    public function matches(Element $element): bool
    {
        return ElementName::matchesUri($element, $this->namespace, $this->localName);
    }

    public function equals(self $other): bool
    {
        return $this->namespace === $other->namespace
            && $this->localName === $other->localName;
    }

    /**
     * The name in the form the locator's failures quote it, so a refusal names the step it refused.
     *
     * @return non-empty-string
     */
    public function toString(): string
    {
        return $this->namespace.':'.$this->localName;
    }
}
