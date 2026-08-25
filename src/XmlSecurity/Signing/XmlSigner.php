<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use VeeWee\Xml\Dom\Document;

/**
 * Builds a detached, multi-reference ds:Signature and inserts it into the document. Mutates the
 * document in place.
 *
 * Returns which external parts the signature covered, so a caller that registered some can assert they were
 * all signed rather than assume it. In-document coverage needs no such report: those references are in the
 * document the caller already holds.
 */
interface XmlSigner
{
    public function sign(Document $document, SigningRequest $request): SignedExternalParts;
}
