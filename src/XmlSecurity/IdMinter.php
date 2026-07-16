<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\Element;
use VeeWee\Xml\Dom\Document;

/**
 * Stamps a document-unique id onto an element so a ds:Reference or xenc:DataReference can address it by
 * URI="#id". The XML-Security engine ships a default that stamps the W3C-standard xml:id (XmlIdMinter); a
 * profile overrides the id convention by supplying its own implementation — the WS-Security profile injects one
 * that stamps wsu:Id, as the spec mandates.
 */
interface IdMinter
{
    /**
     * @return non-empty-string the minted id, without the '#' fragment prefix
     */
    public function mint(Element $node, Document $document): string;
}
