<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Parser;

use SensitiveParameter;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\KeyStore\Pkcs12Bundle;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\Pkcs12Exception;

/**
 * The single openssl_pkcs12_read boundary: it decodes a PKCS#12 blob into the leaf certificate, its already
 * decrypted private key and any embedded CA chain, returning them as the typed value objects the key store
 * builds on. The read runs through OpenSslCall so the openssl warning, whose text can carry key material, is
 * captured instead of emitted and the passphrase never reaches an exception message.
 */
final class Pkcs12Parser
{
    /**
     * @throws Pkcs12Exception when the blob cannot be read or lacks a certificate or key
     */
    public function parse(#[SensitiveParameter] string $contents, #[SensitiveParameter] string $passphrase): Pkcs12Bundle
    {
        $parsed = [];
        [$read] = OpenSslCall::capture(static function () use ($contents, $passphrase, &$parsed): bool {
            return openssl_pkcs12_read($contents, $parsed, $passphrase);
        });

        if ($read !== true) {
            throw Pkcs12Exception::unreadable();
        }

        /** @var array{cert?: string, pkey?: string, extracerts?: list<string>} $parsed */
        $leafPem = $parsed['cert'] ?? '';
        $keyPem = $parsed['pkey'] ?? '';
        if ($leafPem === '' || $keyPem === '') {
            throw Pkcs12Exception::unreadable();
        }

        $chain = [new Certificate($leafPem)];
        foreach ($parsed['extracerts'] ?? [] as $caPem) {
            if ($caPem !== '') {
                $chain[] = new Certificate($caPem);
            }
        }

        return new Pkcs12Bundle(CertificateChain::fromCertificates(...$chain), new Key($keyPem));
    }
}
