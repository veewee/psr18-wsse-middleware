<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Algorithm;

use LogicException;

/**
 * Signature algorithms the engine can sign and verify with. Which are *accepted* is governed by the
 * SecurityProfile allow-list, not by this enum.
 *
 * The HMAC methods are keyed by a shared secret rather than by a certificate, so keyKind() is what a consumer
 * decides on: pairing an HMAC method with a key that came from a certificate is the algorithm-confusion
 * forgery, since the "secret" would be public key bytes anyone holds.
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
    case HMAC_SHA1 = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';
    case HMAC_SHA224 = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha224';
    case HMAC_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256';
    case HMAC_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha384';
    case HMAC_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha512';

    public static function default(): self
    {
        return self::RSA_SHA256;
    }

    /**
     * Which kind of key this method signs and verifies with.
     *
     * Every case is named rather than defaulted: this decides between a certificate and a shared secret, and
     * between two incompatible signature-value encodings, so a case added later must become a static-analysis
     * error here instead of silently taking the RSA route.
     */
    public function keyKind(): SignatureKeyKind
    {
        return match ($this) {
            self::RSA_SHA1, self::RSA_SHA256, self::RSA_SHA384, self::RSA_SHA512 => SignatureKeyKind::Rsa,
            self::DSA_SHA1 => SignatureKeyKind::Dsa,
            self::ECDSA_SHA256, self::ECDSA_SHA384, self::ECDSA_SHA512 => SignatureKeyKind::Ecdsa,
            self::HMAC_SHA1,
            self::HMAC_SHA224,
            self::HMAC_SHA256,
            self::HMAC_SHA384,
            self::HMAC_SHA512 => SignatureKeyKind::Hmac,
        };
    }

    /**
     * The key length this MAC is keyed with, which is its digest size. A shorter key is padded and a longer one
     * is hashed down, so this is the length at which the MAC carries its full strength rather than a
     * requirement.
     *
     * @return positive-int
     *
     * @throws LogicException when the method is not an HMAC one, which keyKind() lets a caller exclude
     */
    public function hmacKeyLength(): int
    {
        return match ($this) {
            self::HMAC_SHA1 => 20,
            self::HMAC_SHA224 => 28,
            self::HMAC_SHA256 => 32,
            self::HMAC_SHA384 => 48,
            self::HMAC_SHA512 => 64,
            self::RSA_SHA1,
            self::RSA_SHA256,
            self::RSA_SHA384,
            self::RSA_SHA512,
            self::DSA_SHA1,
            self::ECDSA_SHA256,
            self::ECDSA_SHA384,
            self::ECDSA_SHA512 => throw new LogicException(sprintf(
                '%s is not an HMAC signature method and has no HMAC key length.',
                $this->name,
            )),
        };
    }
}
