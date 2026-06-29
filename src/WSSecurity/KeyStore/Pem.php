<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore;

/**
 * One or more certificates concatenated into a single PEM bundle, the form a trusted-CA or intermediates file
 * carries. Holds public certificate text only, never key material.
 */
final readonly class Pem
{
    private function __construct(
        private string $value,
    ) {
    }

    public static function fromCertificates(Certificate ...$certificates): self
    {
        return new self(implode("\n", array_map(
            static fn (Certificate $certificate): string => $certificate->contents(),
            $certificates,
        )));
    }

    public function toString(): string
    {
        return $this->value;
    }
}
