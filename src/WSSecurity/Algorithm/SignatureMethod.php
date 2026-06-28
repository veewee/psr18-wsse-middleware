<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Algorithm;

/**
 * Asymmetric signature algorithms the engine can sign and verify with. Which are *accepted* is governed by
 * the SecurityProfile allow-list, not by this enum.
 */
enum SignatureMethod: string
{
    case RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    case RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    case RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    case RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    case DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';
    case ECDSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
    case ECDSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
    case ECDSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512';

    public static function default(): self
    {
        return self::RSA_SHA256;
    }

    /**
     * ECDSA produces a SignatureValue in the fixed-width r||s encoding rather than the DER that OpenSSL emits,
     * so the signer must convert around the OpenSSL boundary for these methods only.
     */
    public function isEcdsa(): bool
    {
        return match ($this) {
            self::ECDSA_SHA256, self::ECDSA_SHA384, self::ECDSA_SHA512 => true,
            default => false,
        };
    }
}
