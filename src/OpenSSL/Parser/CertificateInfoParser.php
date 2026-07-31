<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Parser;

use Psl\DateTime\Timestamp;
use Psl\Type\Exception\CoercionException;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\CertificateInfo;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\IssuerSerial;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\KeyUsage;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\SerialNumber;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\Thumbprint;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\ValidityWindow;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use function Psl\Type\int;
use function Psl\Type\non_empty_string;
use function Psl\Type\optional;
use function Psl\Type\shape;

/**
 * Reads a certificate's fields at the ext-openssl boundary and assembles them into a CertificateInfo: the
 * structured field parse, the fingerprint hash and the serial-number conversion all happen here, so the
 * value objects stay free of openssl and the engine keeps every openssl_* call inside this namespace.
 */
final class CertificateInfoParser
{
    /**
     * @throws CryptoOperationFailed when the certificate cannot be read
     */
    public function parse(Certificate $certificate): CertificateInfo
    {
        // The subject and issuer come from the encoded name sequence, not from openssl's flattened map:
        // only the sequence keeps the relative-name boundaries RFC 2253 rendering depends on.
        $names = (new DistinguishedNameParser())->parse($certificate);

        try {
            $fields = shape([
                'serialNumber' => non_empty_string(),
                'serialNumberHex' => optional(non_empty_string()),
                'validFrom_time_t' => int(),
                'validTo_time_t' => int(),
                'extensions' => optional(shape([
                    'subjectKeyIdentifier' => optional(non_empty_string()),
                    'keyUsage' => optional(non_empty_string()),
                ])),
            ])->coerce(OpenSslCall::run(
                static fn () => openssl_x509_parse($certificate->contents()),
                'read the certificate',
            ));

            $fingerprint = OpenSslCall::run(
                static fn () => openssl_x509_fingerprint($certificate->contents(), 'sha1', true),
                'read the certificate fingerprint',
            );
        } catch (OpenSslException | CoercionException) {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        // The hash is never empty; the guard also keeps the fingerprint typed as a non-empty string.
        if ($fingerprint === '') {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        $subjectKeyIdentifierHex = $fields['extensions']['subjectKeyIdentifier'] ?? null;
        $keyUsage = $fields['extensions']['keyUsage'] ?? null;

        return new CertificateInfo(
            $names['subject'],
            new IssuerSerial(
                $names['issuer'],
                // serialNumberHex states its base; serialNumber is decimal on some builds and hexadecimal on
                // others, so an all-digit value there cannot be read without guessing.
                isset($fields['serialNumberHex'])
                    ? SerialNumber::fromHex($fields['serialNumberHex'])
                    : SerialNumber::fromRaw($fields['serialNumber']),
            ),
            new ValidityWindow(
                Timestamp::fromParts($fields['validFrom_time_t']),
                Timestamp::fromParts($fields['validTo_time_t']),
            ),
            $subjectKeyIdentifierHex !== null ? SubjectKeyIdentifier::fromHex($subjectKeyIdentifierHex) : null,
            $keyUsage !== null ? KeyUsage::fromExtension($keyUsage) : null,
            Thumbprint::fromRawBytes($fingerprint),
            (new PublicKeyStrengthParser())->parse($certificate),
        );
    }

}
