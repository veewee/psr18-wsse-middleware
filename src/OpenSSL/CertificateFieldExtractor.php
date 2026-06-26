<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use Psl\Type\Exception\CoercionException;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use function Psl\Type\non_empty_string;
use function Psl\Type\optional;
use function Psl\Type\shape;

/**
 * Extracts the certificate fields that WSSE key-reference strategies embed in ds:KeyInfo. All reads go through
 * OpenSslCall so the single ext-openssl boundary stays inside the OpenSSL namespace and the strategies remain
 * free of raw openssl_* calls.
 */
final class CertificateFieldExtractor
{
    /**
     * The base64-encoded Subject Key Identifier bytes. The extension value is the colon-separated hex form
     * (e.g. "12:AB:CD"); it is converted to raw bytes and base64-encoded, the form a wsse:KeyIdentifier carries.
     *
     * @return non-empty-string
     *
     * @throws CryptoOperationFailed when the certificate cannot be read or carries no Subject Key Identifier
     */
    public function subjectKeyIdentifier(Certificate $certificate): string
    {
        $info = $this->parse($certificate);
        $hex = $info['extensions']['subjectKeyIdentifier'] ?? null;
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

    /**
     * The X.509 issuer distinguished name and the decimal serial number, as needed by ds:X509IssuerSerial.
     *
     * @return array{issuerName: non-empty-string, serialNumber: non-empty-string}
     *
     * @throws CryptoOperationFailed when the certificate cannot be read
     */
    public function issuerSerial(Certificate $certificate): array
    {
        $info = $this->parse($certificate);

        return [
            'issuerName' => $info['name'],
            'serialNumber' => $info['serialNumber'],
        ];
    }

    /**
     * The SHA-1 fingerprint of the DER-encoded certificate, base64-encoded. This is the value a
     * wsse11:KeyIdentifier carries with the ThumbprintSHA1 ValueType.
     *
     * @return non-empty-string
     *
     * @throws CryptoOperationFailed when the certificate cannot be read
     */
    public function thumbprintSha1(Certificate $certificate): string
    {
        try {
            $fingerprint = OpenSslCall::run(
                static fn () => openssl_x509_fingerprint($certificate->contents(), 'sha1', true),
                'read the certificate fingerprint',
            );
        } catch (OpenSslException) {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        if ($fingerprint === '') {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return base64_encode($fingerprint);
    }

    /**
     * Reads the identifying fields out of openssl_x509_parse's untyped array. coerce() keeps the fields modelled
     * here typed and drops the rest; a CoercionException means a required field is absent, i.e. the certificate
     * is unparseable. The subjectKeyIdentifier extension is optional (present only when the cert carries it).
     *
     * @return array{name: non-empty-string, serialNumber: non-empty-string, extensions?: array{subjectKeyIdentifier?: non-empty-string}}
     */
    private function parse(Certificate $certificate): array
    {
        try {
            return shape([
                'name' => non_empty_string(),
                'serialNumber' => non_empty_string(),
                'extensions' => optional(shape([
                    'subjectKeyIdentifier' => optional(non_empty_string()),
                ])),
            ])->coerce(OpenSslCall::run(
                static fn () => openssl_x509_parse($certificate->contents()),
                'read the certificate',
            ));
        } catch (OpenSslException | CoercionException) {
            throw CryptoOperationFailed::unreadableCertificate();
        }
    }
}
