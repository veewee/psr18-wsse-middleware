<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Parser;

use ParagonIE\HiddenString\HiddenString;
use Psl\Ref;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\InvalidKeyException;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\KeyHandleResolver;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;

final class PrivateKeyParser
{
    public function __invoke(#[SensitiveParameter] HiddenString $privateKey, #[SensitiveParameter] ?HiddenString $password = null): Key
    {
        $passphraseString = $password?->getString() ?? '';
        $passphrase = $passphraseString === '' ? null : $passphraseString;
        $key = (new Key($privateKey->getString()))->withPassphrase($passphraseString);

        try {
            // The openssl_pkey_get_private boundary lives once, in KeyHandleResolver; here we only normalise
            // the parsed key back to a PEM Key value object.
            $handle = KeyHandleResolver::privateKey($key);
            $parsed = OpenSslCall::output(
                static fn (Ref $parsed): bool => openssl_pkey_export($handle, $parsed->value, $passphrase),
                'read the private key',
            );
        } catch (OpenSslException) {
            throw InvalidKeyException::unableToReadPrivateKey();
        }

        return (new Key($parsed))->withPassphrase($passphraseString);
    }
}
