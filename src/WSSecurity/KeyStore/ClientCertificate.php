<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore;

use ParagonIE\HiddenString\HiddenString;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\PrivateKeyParser;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\X509PublicCertificateParser;
use function Psl\File\read;

/**
 * Contains a PEM bundle of both public X.509 Certificate and an (un)encrypted private key PKCS_8.
 */
final class ClientCertificate implements KeyInterface
{
    private HiddenString $key;
    private HiddenString $passphrase;

    public function __construct(#[SensitiveParameter] string $key)
    {
        $this->key = new HiddenString($key);
        $this->passphrase = new HiddenString('');
    }

    /**
     * @param non-empty-string $file
     */
    public static function fromFile(string $file): self
    {
        return new self(read($file));
    }

    /**
     * Loads the certificate-and-key bundle straight from a PKCS#12 blob. The passphrase only decrypts the
     * blob; the extracted private key is already in plain PEM, so no withPassphrase() is needed afterwards.
     */
    public static function fromPkcs12(#[SensitiveParameter] string $contents, #[SensitiveParameter] string $passphrase = ''): self
    {
        $bundle = Pkcs12Bundle::read($contents, $passphrase);

        return new self($bundle->privateKey.$bundle->certificate);
    }

    /**
     * @param non-empty-string $file
     */
    public static function fromPkcs12File(string $file, #[SensitiveParameter] string $passphrase = ''): self
    {
        return self::fromPkcs12(read($file), $passphrase);
    }

    /**
     * Parse out the private part of the bundled X509 certificate.
     */
    public function privateKey(): Key
    {
        return (new PrivateKeyParser())($this->key, $this->passphrase);
    }

    /**
     * Parse out the public part of the bundled X509 certificate.
     */
    public function publicCertificate(): Certificate
    {
        return (new X509PublicCertificateParser())($this->key);
    }

    /**
     * Provides the full content of the bundled pem certificate.
     */
    public function contents(): string
    {
        return $this->key->getString();
    }

    public function passphrase(): string
    {
        return $this->passphrase->getString();
    }

    public function withPassphrase(#[SensitiveParameter] string $passphrase): self
    {
        $new = clone $this;
        $new->passphrase = new HiddenString($passphrase);

        return $new;
    }
}
