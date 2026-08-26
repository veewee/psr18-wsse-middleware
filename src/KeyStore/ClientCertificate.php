<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore;

use InvalidArgumentException;
use ParagonIE\HiddenString\HiddenString;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidPemBundle;
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
    private ?Certificate $publicCertificate = null;

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
     * Parse out the public part of the bundled X509 certificate: the end-entity certificate, whatever position
     * the file lists it in.
     *
     * A combined file may put its CA certificate ahead of the end-entity one, and exports made by hand
     * routinely do. Taking the first certificate in the file would then advertise the CA in the binary
     * security token while the message is signed with the leaf's key, so the leaf is derived from issuer
     * linkage instead.
     *
     * @throws InvalidPemBundle when the bundle holds no certificate, or a block is truncated or nested
     * @throws InvalidArgumentException when no single certificate in the bundle is the end-entity one
     */
    public function publicCertificate(): Certificate
    {
        // Derived once per instance: the outbound signature block asks for this certificate several times per
        // message, and finding the end-entity reads every certificate in the bundle. It does not depend on the
        // passphrase, so withPassphrase() carrying it over to the clone is correct.
        return $this->publicCertificate ??= $this->endEntityCertificate();
    }

    private function endEntityCertificate(): Certificate
    {
        // Deliberately the certificates-only read: whether the bundle's key material makes sense is
        // privateKey()'s question, and asking for the certificate must not fail over the answer.
        $leaf = CertificateChain::fromUnorderedCertificates(
            ...Pem::certificatesIn($this->key->getString()),
        )->leaf();

        return (new X509PublicCertificateParser())(new HiddenString($leaf->contents()));
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
