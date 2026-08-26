<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore\Metadata;

/**
 * The family of a certificate's public key, as far as a key-strength floor needs to distinguish them. RSA and
 * DSA share a floor because both are sized by a modulus in the same range; an elliptic-curve key of the same
 * bit count is far stronger, so it is measured separately. Anything else is Other, which no floor applies to.
 */
enum PublicKeyFamily
{
    case Rsa;
    case Dsa;
    case Ec;
    case Other;
}
