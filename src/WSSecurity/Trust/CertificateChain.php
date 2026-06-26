<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Trust;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;

/**
 * An ordered certificate chain (leaf first) extracted from a BST / ds:KeyInfo. A value object only: it does
 * not validate trust. That is done by OpenSSL\CertificateTrust against a TrustStore.
 */
final class CertificateChain
{
    /** @var non-empty-list<Certificate> */
    private readonly array $certificates;

    private function __construct(Certificate ...$certificates)
    {
        if ($certificates === []) {
            throw new InvalidArgumentException('A certificate chain requires at least one certificate.');
        }

        $this->certificates = array_values($certificates);
    }

    public static function fromCertificates(Certificate ...$certificates): self
    {
        return new self(...$certificates);
    }

    public function leaf(): Certificate
    {
        return $this->certificates[0];
    }

    /**
     * @return non-empty-list<Certificate>
     */
    public function all(): array
    {
        return $this->certificates;
    }
}
