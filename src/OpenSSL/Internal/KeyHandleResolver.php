<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Internal;

use OpenSSLAsymmetricKey;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;

/**
 * Turns the HiddenString-backed KeyStore PEM value objects into live openssl key handles. This is the only
 * place an asymmetric handle is produced for the crypto primitives, so a raw OpenSSLAsymmetricKey is created,
 * used and discarded entirely within the OpenSSL\ module and never escapes it.
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
