<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\Element;
use VeeWee\Xml\Dom\Document;

/**
 * Stamps a document-unique id onto an element so a ds:Reference or xenc:DataReference can address it by
 * URI="#id". The XML-Security engine ships a default that stamps the W3C-standard xml:id
 * (AttributeIdConvention::xmlId()); a profile overrides the convention by supplying its own attribute — the
 * WS-Security profile supplies wsu:Id, as the spec mandates.
 *
 * A minter is never chosen on its own: it is one half of an IdConvention, whose other half is the IdLookup that
 * resolves an id back to its element. Take the pair, never one side.
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
