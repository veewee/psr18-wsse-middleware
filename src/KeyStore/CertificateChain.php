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

    /**
     * Orders a set of certificates whose sequence carries no meaning. A message may hand over a whole
     * certification path with nothing stating which certificate is the end-entity — XML-DSig says as much of
     * ds:X509Data — so the leaf is derived: it is the certificate that issued none of the others.
     *
     * Exactly one such certificate must exist. With none the set is circular or the leaf is missing; with
     * several nothing says which key signed, and choosing one would let the sender decide which certificate a
     * signature is checked against.
     *
     * @throws InvalidArgumentException when the set is empty or has no single end-entity
     */
    public static function fromUnorderedCertificates(Certificate ...$certificates): self
    {
        if (count($certificates) <= 1) {
            return new self(...$certificates);
        }

        $leaves = array_values(array_filter(
            $certificates,
            static function (Certificate $candidate) use ($certificates): bool {
                foreach ($certificates as $other) {
                    if ($other !== $candidate && $other->info()->issuerSerial()->issuer->equals($candidate->info()->subject())) {
                        return false;
                    }
                }

                return true;
            },
        ));

        if (count($leaves) !== 1) {
            throw new InvalidArgumentException('The certificate set has no single end-entity certificate.');
        }

        $leaf = $leaves[0];

        return new self($leaf, ...array_values(array_filter(
            $certificates,
            static fn (Certificate $certificate): bool => $certificate !== $leaf,
        )));
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
