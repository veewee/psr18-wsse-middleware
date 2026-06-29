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

    public function permitsSigning(): bool
    {
        return str_contains($this->value, 'Digital Signature');
    }
}
