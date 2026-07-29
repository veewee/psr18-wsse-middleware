<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\XPath;
use InvalidArgumentException;

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
        // A prefixed name has exactly one colon with a non-empty part on each side. Anything else would leave a
        // local name that addresses no attribute, and since the derivation is what removes the chance of the two
        // spellings disagreeing, it has to refuse what it cannot derive from rather than produce an empty or
        // colon-bearing local name that silently matches nothing.
        $parts = explode(':', $qualifiedName);
        $localName = end($parts);
        if (count($parts) > 2 || $parts[0] === '' || $localName === '') {
            throw new InvalidArgumentException(
                sprintf('"%s" is not a usable attribute name: expected LocalName or Prefix:LocalName.', $qualifiedName),
            );
        }

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
     * namespace is bound to the `xml` prefix everywhere by definition, so binding it again is redundant rather
     * than wrong, and passing it anyway keeps this convention on the same path as every other one.
     */
    public static function xmlId(): self
    {
        return new self('http://www.w3.org/XML/1998/namespace', 'xml:id');
    }

    /**
     * The prefix-to-URI binding a query over this attribute needs, which the caller passes along with the query.
     * The engine runs such a query without knowing which specification the attribute belongs to.
     *
     * @return array<non-empty-string, non-empty-string>
     */
    public function binding(): array
    {
        $colon = strpos($this->qualifiedName, ':');
        if ($colon === false) {
            return [];
        }

        /** @var non-empty-string $prefix */
        $prefix = substr($this->qualifiedName, 0, $colon);

        return [$prefix => $this->namespaceUri];
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
