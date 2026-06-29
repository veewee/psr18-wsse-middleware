<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata;

use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;

/**
 * The SHA-1 fingerprint bytes of a DER-encoded certificate. It renders to the base64 form a wsse11:KeyIdentifier
 * carries with the ThumbprintSHA1 value type and compares against another thumbprint, so a key reference can be
 * matched without leaving the value as a loose base64 string. A distinct type from a Subject Key Identifier so
 * the two kinds of identifier can never be compared to one another.
 */
final readonly class Thumbprint
{
    /**
     * @param non-empty-string $bytes
     */
    private function __construct(
        private string $bytes,
    ) {
    }

    /**
     * @throws CryptoOperationFailed when no fingerprint bytes are given
     */
    public static function fromRawBytes(string $bytes): self
    {
        if ($bytes === '') {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return new self($bytes);
    }

    /**
     * @throws CryptoOperationFailed when the value is not valid base64
     */
    public static function fromBase64(string $base64): self
    {
        $bytes = base64_decode($base64, true);
        if ($bytes === false || $bytes === '') {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return new self($bytes);
    }

    /**
     * @return non-empty-string
     */
    public function toBase64(): string
    {
        return base64_encode($this->bytes);
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->bytes, $other->bytes);
    }
}
