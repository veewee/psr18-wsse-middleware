<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Formatter;

use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;

/**
 * Renders a Subject Key Identifier extension value into the base64 form a wsse:KeyIdentifier carries. The
 * extension value is the colon-separated hex of the identifier octets; it is converted to raw bytes and
 * base64-encoded.
 */
final class SubjectKeyIdentifierFormatter
{
    /**
     * @param non-empty-string|null $hex the colon-separated hex extension value, or null when absent
     *
     * @return non-empty-string
     *
     * @throws CryptoOperationFailed when the certificate carries no Subject Key Identifier
     */
    public function format(?string $hex): string
    {
        if ($hex === null) {
            throw CryptoOperationFailed::missingCertificateField('subjectKeyIdentifier');
        }

        // Some OpenSSL builds render the identifier with a leading "keyid:" marker before the hex octets.
        if (str_starts_with(strtolower($hex), 'keyid:')) {
            $hex = substr($hex, 6);
        }

        $bytes = hex2bin(str_replace(':', '', $hex));
        if ($bytes === false || $bytes === '') {
            throw CryptoOperationFailed::missingCertificateField('subjectKeyIdentifier');
        }

        return base64_encode($bytes);
    }
}
