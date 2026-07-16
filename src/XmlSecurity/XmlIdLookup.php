<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\Element;
use Dom\XPath;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\Query;
use VeeWee\Xml\Dom\Collection\NodeList;
use VeeWee\Xml\Dom\Document;

/**
 * The engine's default IdLookup: resolves an id through the W3C-standard xml:id attribute, so a standalone
 * caller can verify or decrypt with zero configuration. The read-side twin of XmlIdMinter.
 *
 * Hardened against XML Signature Wrapping: it matches only xml:id through an anchored XPath, never
 * getElementById or DTD-declared IDs; the id is embedded as an XPath string literal so a crafted value cannot
 * alter the query; and a duplicate xml:id is rejected as ambiguous rather than resolving to the first match.
 */
final class XmlIdLookup implements IdLookup
{
    /**
     * @param non-empty-string $id
     *
     * @throws IdReferenceException
     */
    public function lookup(Document $document, string $id): Element
    {
        $elements = $this->matching($document, $id);

        return match ($elements->count()) {
            0 => throw IdReferenceException::notFound($id),
            1 => $elements->expectSingle(),
            default => throw IdReferenceException::ambiguous($id),
        };
    }

    /**
     * @return NodeList<Element>
     */
    private function matching(Document $document, string $id): NodeList
    {
        // The xml prefix is bound to the XML namespace for every XPath, so no namespace registration is needed.
        return Query::elements($document, '//*[@xml:id='.XPath::quote($id).']');
    }
}
