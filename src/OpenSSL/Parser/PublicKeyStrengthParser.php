<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Parser;

use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\PublicKeyFamily;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\PublicKeyStrength;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;

/**
 * Reads a certificate's public key family and size at the ext-openssl boundary. Both come from the same
 * openssl call and only mean anything together, so they are parsed as one value: 256 bits is a strong
 * elliptic-curve key and a broken RSA one.
 *
 * A key that cannot be read yields null rather than an exception, so a caller decides what an unmeasurable key
 * means for it. The verifier refuses one: this parser reads through ext-openssl while signatures are verified
 * through phpseclib, so a key unreadable here is not thereby unusable there.
 */
final class PublicKeyStrengthParser
{
    public function parse(Certificate $certificate): ?PublicKeyStrength
    {
        // capture rather than run: an unreadable key is answered with null, and the warning still has to be
        // boxed and the error queue drained so it cannot surface against a later call.
        [$key] = OpenSslCall::capture(static fn () => openssl_pkey_get_public($certificate->contents()));
        if ($key === false) {
            return null;
        }

        [$details] = OpenSslCall::capture(static fn () => openssl_pkey_get_details($key));
        if ($details === false) {
            return null;
        }

        $bits = $details['bits'] ?? null;
        $type = $details['type'] ?? null;
        if (!is_int($bits) || !is_int($type)) {
            return null;
        }

        return new PublicKeyStrength($this->family($type), $bits);
    }

    private function family(int $type): PublicKeyFamily
    {
        return match ($type) {
            OPENSSL_KEYTYPE_RSA => PublicKeyFamily::Rsa,
            OPENSSL_KEYTYPE_DSA => PublicKeyFamily::Dsa,
            OPENSSL_KEYTYPE_EC => PublicKeyFamily::Ec,
            default => PublicKeyFamily::Other,
        };
    }
}
