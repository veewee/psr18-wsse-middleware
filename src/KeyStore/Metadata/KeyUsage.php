<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore\Metadata;

/**
 * The keyUsage extension of a certificate, as openssl renders it. It answers whether the certificate is
 * permitted to produce digital signatures, the only usage the engine asks about.
 */
final readonly class KeyUsage
{
    private function __construct(
        private string $value,
    ) {
    }

    public static function fromExtension(string $value): self
    {
        return new self($value);
    }

    /**
     * Either signing bit permits signing. digitalSignature is the common one, but nonRepudiation (renamed
     * contentCommitment) is defined for verifying signatures too, and qualified-signature PKIs issue signing
     * certificates carrying only that bit — refusing those would be stricter than the peers this library
     * interoperates with.
     */
    public function permitsSigning(): bool
    {
        return str_contains($this->value, 'Digital Signature')
            || str_contains($this->value, 'Non Repudiation');
    }
}
