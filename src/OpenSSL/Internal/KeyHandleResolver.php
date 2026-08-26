<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Internal;

use OpenSSLAsymmetricKey;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;

/**
 * Turns the HiddenString-backed KeyStore PEM value objects into live openssl key handles, for the parsing that
 * reads a key's own properties. A raw OpenSSLAsymmetricKey is created, used and discarded entirely within the
 * OpenSSL\ module and never escapes it.
 *
 * It is not the boundary the crypto primitives go through. Signing, verification and RSA key transport load
 * their keys with phpseclib instead, so an audit of where unwrapped key material is handled has to read those
 * classes as well as this one.
 *
 * @internal
 */
final class KeyHandleResolver
{
    public static function privateKey(#[SensitiveParameter] Key $key): OpenSSLAsymmetricKey
    {
        $raw = $key->passphrase();
        $passphrase = $raw === '' ? null : $raw;

        return OpenSslCall::run(
            static fn (): OpenSSLAsymmetricKey|false => openssl_pkey_get_private($key->contents(), $passphrase),
            'read the private key',
        );
    }

    public static function publicKey(Certificate $certificate): OpenSSLAsymmetricKey
    {
        return OpenSslCall::run(
            static fn (): OpenSSLAsymmetricKey|false => openssl_pkey_get_public($certificate->contents()),
            'read the public key',
        );
    }
}
