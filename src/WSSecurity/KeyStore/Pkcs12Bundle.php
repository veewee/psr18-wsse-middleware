<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore;

use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\Pkcs12Parser;
use function Psl\File\read;

/**
 * The decoded contents of a PKCS#12 blob: the certificate chain (the leaf first, then any embedded CA
 * certificates) and the already-decrypted private key. The key material is held inside the Key and Certificate
 * value objects, which keep it out of exception messages and var dumps.
 */
final class Pkcs12Bundle
{
    public function __construct(
        public readonly CertificateChain $chain,
        public readonly Key $privateKey,
    ) {
    }

    public static function fromString(#[SensitiveParameter] string $contents, #[SensitiveParameter] string $passphrase = ''): self
    {
        return (new Pkcs12Parser())->parse($contents, $passphrase);
    }

    /**
     * @param non-empty-string $file
     */
    public static function fromFile(string $file, #[SensitiveParameter] string $passphrase = ''): self
    {
        return self::fromString(read($file), $passphrase);
    }

    public function leaf(): Certificate
    {
        return $this->chain->leaf();
    }
}
