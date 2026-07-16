<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\Locator\WsuId;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use VeeWee\Xml\Dom\Document;

/**
 * The WS-Security profile's IdLookup: resolves an id through the wsu:Id attribute the spec mandates, the
 * read-side twin of WsuIdMinter. Delegates to the hardened WsuId locator, which refuses a duplicate id and
 * never falls back to getElementById.
 */
final class WsuIdLookup implements IdLookup
{
    /**
     * @param non-empty-string $id
     */
    public function lookup(Document $document, string $id): Element
    {
        return WsuId::resolve($document, $id);
    }
}
