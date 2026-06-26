<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Algorithm;

/**
 * XML-DSig signature algorithms. All cases are representable for interop parity; which are *accepted*
 * is governed by the SecurityProfile allow-list, not by this enum.
 */
enum SignatureMethod: string
{
    case RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    case RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    case RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    case RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    case DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';
    case HMAC_SHA1 = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';
    case HMAC_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256';

    public static function default(): self
    {
        return self::RSA_SHA256;
    }
}
