<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use VeeWee\Xml\Dom\Document;

/**
 * The per-message state a block needs to act on the message: the document being secured, its SOAP
 * version, and the effective security profile for the message. One context is created per message and
 * passed to each block in the list. Blocks receive their services (randomness, digests, certificates)
 * by constructor injection, not from here; this object carries only what is unique to the message in
 * flight together with the profile that governs it.
 */
final class WsseContext
{
    public function __construct(
        private readonly Document $document,
        private readonly SoapVersion $soapVersion,
        private readonly SecurityProfile $profile,
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

    public function profile(): SecurityProfile
    {
        return $this->profile;
    }
}
