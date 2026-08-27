<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use VeeWee\Xml\Dom\Document;

/**
 * The per-message state a block needs to act on the message: the document being secured, its SOAP
 * version, the effective security profile, and the symmetric keys of the exchange. One context is created per
 * message and passed to each block in the list. Blocks receive their services (randomness, digests,
 * certificates) by constructor injection, not from here; this object carries only what is unique to the message
 * in flight together with the profile that governs it.
 *
 * The exchange keys are the one thing here that outlives a single message: the request context and the response
 * context of one exchange share the instance, which is how a response is verified and decrypted against a key
 * the request established. It is scoped to that exchange and to nothing wider.
 */
final class WsseContext
{
    public function __construct(
        private readonly Document $document,
        private readonly SoapVersion $soapVersion,
        private readonly SecurityProfile $profile,
        private readonly ExchangeKeys $keys,
    ) {
    }

    public function keys(): ExchangeKeys
    {
        return $this->keys;
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
