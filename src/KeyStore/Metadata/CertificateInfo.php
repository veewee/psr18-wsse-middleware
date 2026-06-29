<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore\Metadata;

use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\CertificateInfoParser;

/**
 * The fields of a certificate a WSSE engine needs, each as its own value object: the values key-reference
 * strategies embed in ds:KeyInfo (subject key identifier, issuer and serial, thumbprint) and the fields trust
 * verification reads (subject name, validity window, key usage). The optional fields are null when the
 * certificate does not carry them.
 */
final readonly class CertificateInfo
{
    public function __construct(
        private DistinguishedName $subject,
        private IssuerSerial $issuerSerial,
        private ValidityWindow $validity,
        private ?SubjectKeyIdentifier $subjectKeyIdentifier,
        private ?KeyUsage $keyUsage,
        private Thumbprint $thumbprint,
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
        return $this->issuerSerial;
    }

    /**
     * @throws CryptoOperationFailed when the certificate carries no Subject Key Identifier
     */
    public function subjectKeyIdentifier(): SubjectKeyIdentifier
    {
        return $this->subjectKeyIdentifier
            ?? throw CryptoOperationFailed::missingCertificateField('subjectKeyIdentifier');
    }

    public function thumbprintSha1(): Thumbprint
    {
        return $this->thumbprint;
    }

    public function validity(): ValidityWindow
    {
        return $this->validity;
    }

    public function keyUsage(): ?KeyUsage
    {
        return $this->keyUsage;
    }
}
