<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use VeeWee\Xml\Dom\Document;

/**
 * Resolves a bare id (a ds:Reference / xenc:DataReference URI without the '#') to the single element carrying
 * it, under one id convention. The read-side twin of IdMinter, and like it never chosen
 * alone: both halves come from one IdConvention. The engine ships an xml:id default
 * (AttributeIdConvention::xmlId()); the WS-Security profile supplies wsu:Id.
 *
 * The lookup is hardened against XML Signature Wrapping: it matches only its own id attribute through an
 * anchored XPath, never getElementById or DTD-declared IDs, and rejects a duplicate id as ambiguous instead of
 * silently resolving to the first match.
 */
interface IdLookup
{
    /**
     * @param non-empty-string $id the bare id value, without the '#' fragment prefix
     *
     * @throws IdReferenceException when no element carries the id, or more than one does
     */
    public function lookup(Document $document, string $id): Element;
}
