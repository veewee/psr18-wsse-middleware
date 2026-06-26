<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use VeeWee\Xml\Dom\Document;

/**
 * The per-message state an outbound block needs to write its token into the request: the document
 * being secured and its SOAP version. One context is created per message and passed to each block in
 * the outbound list. Blocks receive their services (randomness, digests, certificates) by constructor
 * injection, not from here; this object carries only what is unique to the message in flight.
 */
final class WsseContext
{
    public function __construct(
        private readonly Document $document,
        private readonly SoapVersion $soapVersion,
    ) {
    }

    public function document(): Document
    {
        return $this->document;
    }

    public function soapVersion(): SoapVersion
    {
        return $this->soapVersion;
    }
}
