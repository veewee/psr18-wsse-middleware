<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

/**
 * Where cipher bytes go when they are not written into the document.
 *
 * A peer may put them somewhere beside the XML and leave a pointer behind, which saves the 33% base64 costs.
 * Whether that somewhere is a MIME part, and what a pointer at it looks like, is the profile's business: the
 * engine hands over octets and is told what to point at. No sink at all is the ordinary case, and then the
 * bytes are base64 in the document as they always were.
 */
interface CipherValueSink
{
    /**
     * @return non-empty-string the URI the xenc:CipherValue points at instead of carrying these bytes
     */
    public function store(string $bytes): string;
}
