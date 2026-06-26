<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

/**
 * Selects which WSSE key-reference type the Encryption block puts in the xenc:EncryptedKey's
 * ds:KeyInfo, so the recipient knows which private key unwraps the session key. One of:
 *   subjectKeyIdentifier() -- inline Subject Key Identifier extension value (the encryption default)
 *   issuerSerial()         -- inline ds:X509IssuerSerial
 *   thumbprint()           -- inline ThumbprintSHA1
 *   binarySecurityToken()  -- embed a wsse:BinarySecurityToken and point at it by wsu:Id (uncommon
 *                            for encryption; provided for parity with the signing path)
 *
 * The named constructors are the only way to build an EncKeyRef, so the kind always stays one of the
 * four supported cases. The Encryption block resolves the kind to a concrete KeyIdentifier strategy.
 */
final readonly class EncKeyRef
{
    private function __construct(private EncKeyRefKind $kind)
    {
    }

    public static function subjectKeyIdentifier(): self
    {
        return new self(EncKeyRefKind::SubjectKeyIdentifier);
    }

    public static function issuerSerial(): self
    {
        return new self(EncKeyRefKind::IssuerSerial);
    }

    public static function thumbprint(): self
    {
        return new self(EncKeyRefKind::Thumbprint);
    }

    public static function binarySecurityToken(): self
    {
        return new self(EncKeyRefKind::DirectReference);
    }

    public function kind(): EncKeyRefKind
    {
        return $this->kind;
    }
}
