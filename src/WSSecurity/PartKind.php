<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

enum PartKind
{
    case Body;
    case Element;
    case Id;

    /**
     * An element named by where it sits rather than only by what it is called: an ordered list of qualified
     * names from the document element down. Body is this shape with the steps filled in for the message's SOAP
     * version, so the two lower the same way.
     */
    case Path;

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

    /**
     * A dynamic part standing for the one ds:Signature already in the Security header: what an endorsing
     * supporting token covers. Resolved against the live header, because the element it names is written by
     * another block rather than being any element of the message.
     */
    case PrimarySignature;

    /**
     * Whether the part stands for a set of elements resolved against the live message rather than lowering to
     * a single Target. A dynamic part can only be resolved once the Security header it is relative to is
     * known, so a caller that cannot identify that header must refuse the part rather than expand it to none.
     */
    public function isDynamic(): bool
    {
        return match ($this) {
            self::SecurityHeaderContents, self::SoapHeaders, self::PrimarySignature => true,
            self::Body, self::Element, self::Id, self::Path => false,
        };
    }
}
