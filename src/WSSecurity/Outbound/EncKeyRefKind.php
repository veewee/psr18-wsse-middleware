<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

/**
 * The discriminant for EncKeyRef. DirectReference requires a wsse:BinarySecurityToken to be embedded
 * before encrypting; the inline references derive their content from the recipient certificate alone.
 */
enum EncKeyRefKind
{
    case SubjectKeyIdentifier;
    case IssuerSerial;
    case Thumbprint;
    case DirectReference;
}
