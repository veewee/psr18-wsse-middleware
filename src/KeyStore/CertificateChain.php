<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore;

use InvalidArgumentException;

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

    /**
     * The certificates above the leaf as one PEM bundle, or null when the chain is the leaf alone. This is the
     * untrusted-intermediates bundle a chain-to-anchor check feeds to the platform verifier.
     */
    public function intermediatesPem(): ?Pem
    {
        $intermediates = array_slice($this->certificates, 1);
        if ($intermediates === []) {
            return null;
        }

        return Pem::fromCertificates(...$intermediates);
    }
}
