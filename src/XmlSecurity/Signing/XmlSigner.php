<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use VeeWee\Xml\Dom\Document;

/**
 * Builds a detached, multi-reference, WSSE-aware ds:Signature and inserts it into the document. Mutates the
 * document in place.
 */
interface XmlSigner
{
    public function sign(Document $document, SigningRequest $request): void;
}
