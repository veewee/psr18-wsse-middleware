<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata;

use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\CertificateInfoParser;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;

/**
 * The fields of a certificate a WSSE engine needs: the values key-reference strategies embed in ds:KeyInfo
 * (subject key identifier, issuer and serial, thumbprint) and the fields trust verification reads (subject
 * name, validity window, key usage). Each field is exposed as its own value object; the optional ones throw
 * only when asked for, so a certificate missing one field still answers for the others.
 */
final readonly class CertificateInfo
{
    /**
     * @param non-empty-string $serialNumber decimal serial number
     * @param non-empty-string|null $subjectKeyIdentifierHex colon-separated hex, or null when the certificate carries none
     * @param non-empty-string|null $keyUsage the keyUsage extension text, or null when absent
     * @param non-empty-string $sha1Fingerprint the raw SHA-1 fingerprint bytes
     */
    public function __construct(
        private DistinguishedName $subject,
        private DistinguishedName $issuer,
        private string $serialNumber,
        private ValidityWindow $validity,
        private ?string $subjectKeyIdentifierHex,
        private ?string $keyUsage,
        private string $sha1Fingerprint,
    ) {
    }

    /**
     * Reads the fields of a certificate through the openssl boundary.
     *
     * @throws CryptoOperationFailed when the certificate cannot be read
     */
    public static function fromCertificate(Certificate $certificate): self
    {
        return (new CertificateInfoParser())->parse($certificate);
    }

    public function subject(): DistinguishedName
    {
        return $this->subject;
    }

    public function issuerSerial(): IssuerSerial
    {
        return new IssuerSerial($this->issuer, $this->serialNumber);
    }

    /**
     * @throws CryptoOperationFailed when the certificate carries no Subject Key Identifier
     */
    public function subjectKeyIdentifier(): SubjectKeyIdentifier
    {
        if ($this->subjectKeyIdentifierHex === null) {
            throw CryptoOperationFailed::missingCertificateField('subjectKeyIdentifier');
        }

        return SubjectKeyIdentifier::fromHex($this->subjectKeyIdentifierHex);
    }

    public function thumbprintSha1(): Thumbprint
    {
        return Thumbprint::fromRawBytes($this->sha1Fingerprint);
    }

    public function validity(): ValidityWindow
    {
        return $this->validity;
    }

    /**
     * @return non-empty-string|null
     */
    public function keyUsage(): ?string
    {
        return $this->keyUsage;
    }
}
