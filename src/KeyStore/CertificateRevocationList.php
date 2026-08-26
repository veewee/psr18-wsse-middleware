<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore;

use function Psl\File\read;

/**
 * A certificate revocation list supplied by the integrator, in PEM form. A credential value object holding
 * bytes only: which issuer it speaks for, when it goes out of date, and which serials it revokes are read at
 * verification time by OpenSSL\RevocationCheck, together with the signature check that decides whether any of
 * it may be believed.
 *
 * Nothing is parsed here, so holding an instance is never evidence the bytes are a usable CRL.
 */
final class CertificateRevocationList
{
    public function __construct(
        private readonly string $pem,
    ) {
    }

    /**
     * @param non-empty-string $file
     */
    public static function fromFile(string $file): self
    {
        return new self(read($file));
    }

    public function contents(): string
    {
        return $this->pem;
    }
}
