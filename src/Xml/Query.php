<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

use Dom\Element;
use Dom\Node;
use VeeWee\Xml\Dom\Collection\NodeList;
use VeeWee\Xml\Dom\Document;

/**
 * Runs an xpath query under the bindings it needs and narrows the result to elements, the shape every namespaced
 * lookup shares. The count rule (first, exactly one, all) and the failure type stay with each caller, so the
 * security intent and the caller's own exception remain visible at the call site.
 *
 * Each caller declares the prefixes its own query uses. Nothing is bound globally, so a layer cannot silently
 * depend on a prefix belonging to a specification above it.
 */
final class Query
{
    /**
     * @param array<non-empty-string, non-empty-string> $prefixes prefix => namespace URI for this query
     *
     * @return NodeList<Element>
     */
    public static function elements(
        Document $document,
        string $xpath,
        ?Node $contextNode = null,
        array $prefixes = [],
    ): NodeList {
        return $document
            ->xpath(new Xpath($document, $prefixes))
            ->query($xpath, $contextNode)
            ->expectAllOfType(Element::class);
    }
}
