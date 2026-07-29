<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\Query;
use Soap\Psr18WsseMiddleware\Xml\UniqueMatch;
use VeeWee\Xml\Dom\Document;

/**
 * Resolves an id under one IdAttribute, the read side of AttributeIdMinter.
 *
 * Hardened against XML Signature Wrapping: it matches only its own attribute through an anchored XPath, never
 * getElementById or DTD-declared IDs; the id is embedded as an XPath string literal so a crafted value cannot
 * alter the query; and a duplicate is rejected as ambiguous rather than resolving to the first match.
 */
final readonly class AttributeIdLookup implements IdLookup
{
    public function __construct(
        private IdAttribute $attribute,
    ) {
    }

    /**
     * @param non-empty-string $id
     *
     * @throws IdReferenceException
     */
    public function lookup(Document $document, string $id): Element
    {
        return UniqueMatch::require(
            Query::elements($document, $this->attribute->matches($id), prefixes: $this->attribute->binding())
                ->map(static fn (Element $element): Element => $element),
            $id,
        );
    }
}
