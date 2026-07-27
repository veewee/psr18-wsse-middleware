<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore;

use ParagonIE\HiddenString\HiddenString;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\PrivateKeyParser;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\X509PublicCertificateParser;
use function Psl\File\read;

/**
 * Contains a PEM bundle of both public X.509 Certificate and an (un)encrypted private key PKCS_8.
 */
final class ClientCertificate
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
     * The certificate-and-key bundle of an already-decoded PKCS#12 bundle. The extracted private key is
     * already in plain PEM, so no withPassphrase() is needed afterwards.
     */
    public static function fromPkcs12(Pkcs12Bundle $bundle): self
    {
        return new self($bundle->privateKey->contents().$bundle->leaf()->contents());
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
