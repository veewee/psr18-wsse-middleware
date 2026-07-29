<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\XPath;

/**
 * The attribute an id convention writes and reads: which namespace it lives in and how it is spelled. This is
 * the whole of what separates one id convention from another, so both sides of a convention are driven from one
 * instance and cannot disagree about it.
 *
 * The local name is derived from the qualified name rather than passed alongside it. Stamping needs the
 * qualified form (`wsu:Id`), reading an attribute node needs the local form (`Id`), and a caller supplying both
 * could supply two that do not match — a mismatch no test would notice until a reference failed to resolve.
 */
final readonly class IdAttribute
{
    /** @var non-empty-string */
    public string $localName;

    /**
     * @param non-empty-string $namespaceUri
     * @param non-empty-string $qualifiedName the prefixed form used when stamping, such as `wsu:Id`
     */
    private function __construct(
        public string $namespaceUri,
        public string $qualifiedName,
    ) {
        $colon = strpos($qualifiedName, ':');
        /** @var non-empty-string $localName */
        $localName = $colon === false ? $qualifiedName : substr($qualifiedName, $colon + 1);
        $this->localName = $localName;
    }

    /**
     * @param non-empty-string $namespaceUri
     * @param non-empty-string $qualifiedName
     */
    public static function of(string $namespaceUri, string $qualifiedName): self
    {
        return new self($namespaceUri, $qualifiedName);
    }

    /**
     * The W3C-standard `xml:id`, which the engine uses unless a profile overrides the convention. The XML
     * namespace is bound to the `xml` prefix everywhere by definition, so no XPath registration is needed.
     */
    public static function xmlId(): self
    {
        return new self('http://www.w3.org/XML/1998/namespace', 'xml:id');
    }

    /**
     * An XPath predicate matching an element that carries this attribute with the given value. The value is
     * embedded as a string literal, so an id crafted to break out of the query cannot.
     */
    public function matches(string $id): string
    {
        return '//*[@'.$this->qualifiedName.'='.XPath::quote($id).']';
    }
}
