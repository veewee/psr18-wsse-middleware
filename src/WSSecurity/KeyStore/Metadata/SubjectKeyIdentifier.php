<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata;

use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;

/**
 * The raw Subject Key Identifier octets of a certificate. It renders to the base64 form a wsse:KeyIdentifier
 * carries and compares against another identifier of the same kind, so a key reference can be matched without
 * leaving the value as a loose base64 string.
 */
final readonly class SubjectKeyIdentifier
{
    /**
     * @param non-empty-string $bytes
     */
    private function __construct(
        private string $bytes,
    ) {
    }

    /**
     * Reads the extension value openssl reports: colon-separated hex octets, optionally prefixed with a
     * "keyid:" marker on some builds.
     *
     * @throws CryptoOperationFailed when the value is absent or not valid hex
     */
    public static function fromHex(string $hex): self
    {
        if (str_starts_with(strtolower($hex), 'keyid:')) {
            $hex = substr($hex, 6);
        }

        $hex = str_replace(':', '', $hex);
        $bytes = $hex !== '' && strlen($hex) % 2 === 0 && ctype_xdigit($hex) ? hex2bin($hex) : false;
        if ($bytes === false || $bytes === '') {
            throw CryptoOperationFailed::missingCertificateField('subjectKeyIdentifier');
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
            throw CryptoOperationFailed::missingCertificateField('subjectKeyIdentifier');
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
