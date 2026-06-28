<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore;

use SensitiveParameter;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\Pkcs12Exception;

/**
 * The decoded contents of a PKCS#12 blob: the leaf certificate, its already-decrypted private key and any
 * embedded CA chain. This is the single openssl_pkcs12_read boundary the key store factories share so the
 * passphrase and the raw OpenSSL error queue stay contained here and never reach an exception message.
 *
 * @internal
 */
final class Pkcs12Bundle
{
    /**
     * @param non-empty-string $certificate
     * @param non-empty-string $privateKey
     * @param list<non-empty-string> $caChain
     */
    private function __construct(
        public readonly string $certificate,
        public readonly string $privateKey,
        public readonly array $caChain,
    ) {
    }

    public static function read(#[SensitiveParameter] string $contents, #[SensitiveParameter] string $passphrase): self
    {
        $parsed = [];

        // Suppress the openssl warning: its text can carry key material, and the boolean return already
        // tells us the read failed. The exception below stays deliberately generic.
        if (!@openssl_pkcs12_read($contents, $parsed, $passphrase)) {
            throw Pkcs12Exception::unreadable();
        }

        /** @var array{cert?: string, pkey?: string, extracerts?: list<string>} $out */
        $out = $parsed;

        $certificate = $out['cert'] ?? '';
        $privateKey = $out['pkey'] ?? '';
        if ($certificate === '' || $privateKey === '') {
            throw Pkcs12Exception::unreadable();
        }

        $caChain = [];
        foreach ($out['extracerts'] ?? [] as $pem) {
            if ($pem !== '') {
                $caChain[] = $pem;
            }
        }

        return new self($certificate, $privateKey, $caChain);
    }
}
