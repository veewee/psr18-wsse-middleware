<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

use Dom\Element;
use Dom\Node;
use VeeWee\Xml\Dom\Collection\NodeList;
use VeeWee\Xml\Dom\Document;

/**
 * Runs an xpath query under the shared namespace bindings and narrows the result to elements, the shape every
 * namespaced lookup shares. The count rule (first, exactly one, all) and the failure type stay with each
 * caller, so the security intent and the caller's own exception remain visible at the call site.
 */
final class Query
{
    /**
     * @return NodeList<Element>
     */
    public static function elements(Document $document, string $xpath, ?Node $contextNode = null): NodeList
    {
        return $document
            ->xpath(new Xpath($document))
            ->query($xpath, $contextNode)
            ->expectAllOfType(Element::class);
    }
}
