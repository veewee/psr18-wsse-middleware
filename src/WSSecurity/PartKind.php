<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

enum PartKind
{
    case Body;
    case Element;
    case Id;

    /**
     * A dynamic part standing for every current child of the wsse:Security header. Unlike the others it does
     * not lower to a single Target: the Signature block expands it against the live header at send time, once
     * the earlier blocks (Timestamp, BinarySecurityToken, ...) have added their elements.
     */
    case SecurityHeaderContents;

    /**
     * A dynamic part standing for every current SOAP header block except the wsse:Security header itself (for
     * example WS-Addressing headers). Like SecurityHeaderContents, the Signature block expands it against the
     * live document at send time.
     */
    case SoapHeaders;
}
