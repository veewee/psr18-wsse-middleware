<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

/**
 * Selects which WSSE key-reference type the Signature block puts in ds:KeyInfo. One of:
 *   BinarySecurityToken  -- embed a wsse:BinarySecurityToken and point at it by wsu:Id (the
 *                           direct-reference interop default for X.509 signing)
 *   SubjectKeyIdentifier -- inline Subject Key Identifier extension value
 *   IssuerSerial         -- inline ds:X509IssuerSerial
 *   Thumbprint           -- inline ThumbprintSHA1
 *
 * BinarySecurityToken requires a wsse:BinarySecurityToken to be embedded before signing; the inline
 * references derive their content from the certificate alone. The Signature block resolves each case
 * to a concrete KeyIdentifier strategy.
 */
enum KeyRef
{
    case BinarySecurityToken;
    case SubjectKeyIdentifier;
    case IssuerSerial;
    case Thumbprint;
}
