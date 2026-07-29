<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo;

/**
 * Which identifier a ds:KeyInfo reference uses to name a certificate it does not carry. Both are properties of
 * the certificate itself rather than of any message format: the Subject Key Identifier extension value, and the
 * SHA-1 fingerprint of the DER certificate.
 *
 * Named semantically, not by URI, so resolving a reference against a store needs no knowledge of the profile the
 * message was written in. Whoever reads ds:KeyInfo translates that profile's spelling into one of these, and an
 * identifier this does not name cannot be resolved -- which is why the translation refuses an unknown spelling
 * where it reads it, rather than passing a string along to fail later.
 */
enum KeyIdentifierKind
{
    case SubjectKeyIdentifier;
    case ThumbprintSha1;
}
