<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

/**
 * Selects which WSSE key-reference type the Signature block puts in ds:KeyInfo. One of:
 *   binarySecurityToken() -- embed a wsse:BinarySecurityToken and point at it by wsu:Id (the
 *                            direct-reference interop default for X.509 signing)
 *   subjectKeyIdentifier() -- inline Subject Key Identifier extension value
 *   issuerSerial()         -- inline ds:X509IssuerSerial
 *   thumbprint()           -- inline ThumbprintSHA1
 *
 * The named constructors are the only way to build a KeyRef, so the kind always stays one of the
 * four supported cases. The Signature block resolves the kind to a concrete KeyIdentifier strategy.
 */
final readonly class KeyRef
{
    private function __construct(private KeyRefKind $kind)
    {
    }

    public static function binarySecurityToken(): self
    {
        return new self(KeyRefKind::DirectReference);
    }

    public static function subjectKeyIdentifier(): self
    {
        return new self(KeyRefKind::SubjectKeyIdentifier);
    }

    public static function issuerSerial(): self
    {
        return new self(KeyRefKind::IssuerSerial);
    }

    public static function thumbprint(): self
    {
        return new self(KeyRefKind::Thumbprint);
    }

    public function kind(): KeyRefKind
    {
        return $this->kind;
    }
}
