<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Formatter\DistinguishedName;
use Soap\Psr18WsseMiddleware\OpenSSL\Formatter\SerialNumber;
use Soap\Psr18WsseMiddleware\OpenSSL\Formatter\SubjectKeyIdentifierFormatter;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\ParsedCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;

/**
 * The single reader of certificate fields: the values WSSE key-reference strategies embed in ds:KeyInfo
 * (subject key identifier, issuer and serial, thumbprint) and the fields trust verification needs (subject
 * name, validity window, key usage). Each call parses the certificate through ParsedCertificate, which owns
 * the ext-openssl boundary, then hands the typed fields to the matching formatter, so callers remain free of
 * raw openssl_* calls.
 */
final class CertificateFieldExtractor
{
    public function __construct(
        private readonly SubjectKeyIdentifierFormatter $subjectKeyIdentifier = new SubjectKeyIdentifierFormatter(),
        private readonly DistinguishedName $distinguishedName = new DistinguishedName(),
        private readonly SerialNumber $serialNumber = new SerialNumber(),
    ) {
    }

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
        return $this->subjectKeyIdentifier->format(
            ParsedCertificate::fromCertificate($certificate)->subjectKeyIdentifierHex(),
        );
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
        $parsed = ParsedCertificate::fromCertificate($certificate);

        return [
            'issuerName' => $this->distinguishedName->render($parsed->issuer()),
            'serialNumber' => $this->serialNumber->toDecimal($parsed->serialNumberRaw()),
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
        return base64_encode(ParsedCertificate::fromCertificate($certificate)->sha1Fingerprint());
    }

    /**
     * The certificate's subject distinguished name, as openssl reports it. Used as the human-readable signer
     * identity once a chain is trusted.
     *
     * @return non-empty-string
     *
     * @throws CryptoOperationFailed when the certificate cannot be read
     */
    public function subjectName(Certificate $certificate): string
    {
        return ParsedCertificate::fromCertificate($certificate)->subjectName();
    }

    /**
     * The certificate's validity window as Unix timestamps, so a verifier can reject a not-yet-valid or expired
     * certificate.
     *
     * @return array{from: int, to: int}
     *
     * @throws CryptoOperationFailed when the certificate cannot be read
     */
    public function validityWindow(Certificate $certificate): array
    {
        $parsed = ParsedCertificate::fromCertificate($certificate);

        return ['from' => $parsed->validFrom(), 'to' => $parsed->validTo()];
    }

    /**
     * The keyUsage extension value, or null when the certificate carries no keyUsage extension.
     *
     * @return non-empty-string|null
     *
     * @throws CryptoOperationFailed when the certificate cannot be read
     */
    public function keyUsage(Certificate $certificate): ?string
    {
        return ParsedCertificate::fromCertificate($certificate)->keyUsage();
    }
}
