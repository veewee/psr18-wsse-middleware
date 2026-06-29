<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Parser;

use ParagonIE\HiddenString\HiddenString;
use Psl\Ref;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\InvalidKeyException;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;

final class X509PublicCertificateParser
{
    public function __invoke(HiddenString $publicKey): Certificate
    {
        try {
            $certificate = OpenSslCall::run(
                static fn () => openssl_x509_read($publicKey->getString()),
                'read the public certificate',
            );
            $parsed = OpenSslCall::output(
                static fn (Ref $parsed): bool => openssl_x509_export($certificate, $parsed->value),
                'read the public certificate',
            );
        } catch (OpenSslException) {
            throw InvalidKeyException::unableToReadPublicKey();
        }

        return new Certificate($parsed);
    }
}
