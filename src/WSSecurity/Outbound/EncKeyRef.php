<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

/**
 * Selects which WSSE key-reference type the Encryption block puts in the xenc:EncryptedKey's
 * ds:KeyInfo, so the recipient knows which private key unwraps the session key. One of:
 *   SubjectKeyIdentifier -- inline Subject Key Identifier extension value (the encryption default)
 *   IssuerSerial         -- inline ds:X509IssuerSerial
 *   Thumbprint           -- inline ThumbprintSHA1
 *   BinarySecurityToken  -- embed a wsse:BinarySecurityToken and point at it by wsu:Id (uncommon
 *                           for encryption; provided for parity with the signing path)
 *
 * BinarySecurityToken requires a wsse:BinarySecurityToken to be embedded before encrypting; the inline
 * references derive their content from the recipient certificate alone. The Encryption block resolves
 * each case to a concrete KeyIdentifier strategy.
 */
enum EncKeyRef
{
    case SubjectKeyIdentifier;
    case IssuerSerial;
    case Thumbprint;
    case BinarySecurityToken;
}
