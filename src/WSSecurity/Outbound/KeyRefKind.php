<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

/**
 * The discriminant for KeyRef. DirectReference requires a wsse:BinarySecurityToken to be embedded
 * before signing; the inline references derive their content from the certificate alone.
 */
enum KeyRefKind
{
    case DirectReference;
    case SubjectKeyIdentifier;
    case IssuerSerial;
    case Thumbprint;
}
