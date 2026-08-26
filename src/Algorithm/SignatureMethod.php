<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Algorithm;

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
     * ECDSA selects an elliptic-curve key for the signer, distinguishing these methods from the RSA and DSA
     * cases that share the enum.
     */
    public function isEcdsa(): bool
    {
        // Every case is named rather than defaulted: this predicate decides between two incompatible
        // signature-value encodings, so a case added later must become a static-analysis error here instead of
        // silently taking the RSA route.
        return match ($this) {
            self::ECDSA_SHA256, self::ECDSA_SHA384, self::ECDSA_SHA512 => true,
            self::RSA_SHA1, self::RSA_SHA256, self::RSA_SHA384, self::RSA_SHA512, self::DSA_SHA1 => false,
        };
    }
}
