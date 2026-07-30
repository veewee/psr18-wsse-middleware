<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore\Metadata;

/**
 * How strong a certificate's public key is: its family and its size in bits. Held as its own value object
 * because the two only mean anything together. 256 bits is a strong elliptic-curve key and a broken RSA one,
 * so a floor can only be compared against a key whose family is known.
 *
 * The family is deliberately coarse. A key this library cannot sign or verify with is Other, and a policy
 * measuring a floor has no size to compare it against.
 */
final readonly class PublicKeyStrength
{
    public function __construct(
        public PublicKeyFamily $family,
        public int $bits,
    ) {
    }
}
