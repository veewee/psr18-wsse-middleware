<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference;

/**
 * Selects which WSSE key-reference type the Signature block puts in ds:KeyInfo. One of:
 *   BinarySecurityToken  -- embed a wsse:BinarySecurityToken and point at it by wsu:Id (the
 *                           direct-reference interop default for X.509 signing)
 *   SubjectKeyIdentifier -- inline Subject Key Identifier extension value
 *   IssuerSerial         -- inline ds:X509IssuerSerial
 *   Thumbprint           -- inline ThumbprintSHA1
 *   SamlAssertion        -- point at the saml:Assertion already in the header (Holder-of-Key)
 *
 * BinarySecurityToken requires a wsse:BinarySecurityToken to be embedded before signing; the inline
 * references derive their content from the certificate alone. CertificateSigningKey resolves each case
 * to a concrete KeyIdentifier strategy, since it is what holds everything certificate-shaped about a
 * signature.
 *
 * BinarySecurityToken and SamlAssertion are the two cases whose target is a token in the message rather
 * than something derived from the certificate: the first embeds that token itself, the second expects an
 * Outbound\SamlAssertion block to have run earlier in the list and finds what it left behind. Neither can
 * be expressed as a value built before the message exists, which is why this is an enum the block resolves
 * per message rather than a key identifier the caller constructs.
 */
enum KeyRef
{
    case BinarySecurityToken;
    case SubjectKeyIdentifier;
    case IssuerSerial;
    case Thumbprint;
    case SamlAssertion;
}
