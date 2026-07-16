<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\Element;
use VeeWee\Xml\Dom\Document;

/**
 * Stamps a document-unique id onto an element so a ds:Reference or xenc:DataReference can address it by
 * URI="#id". The XML-Security engine ships a default that stamps the W3C-standard xml:id (XmlIdMinter); a
 * profile overrides the id convention by supplying its own implementation — the WS-Security profile injects one
 * that stamps wsu:Id, as the spec mandates. Whichever implementation is chosen must be paired with the matching
 * IdLookup, the read-side twin that resolves an id back to its element.
 */
interface IdMinter
{
    /**
     * Ensures the node carries an id under this minter's id convention and returns it. Idempotent: a node that
     * already carries one (stamped by an earlier block, such as a Timestamp or BinarySecurityToken) keeps that
     * id rather than receiving a second, so a ds:Reference addresses the same value the earlier block emitted.
     *
     * @return non-empty-string the id, without the '#' fragment prefix
     */
    public function mint(Element $node, Document $document): string;
}
