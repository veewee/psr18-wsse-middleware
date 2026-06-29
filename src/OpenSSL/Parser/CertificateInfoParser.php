<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Parser;

use Psl\DateTime\Timestamp;
use Psl\Type\Exception\CoercionException;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\CertificateInfo;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\ValidityWindow;
use function Psl\Type\dict;
use function Psl\Type\int;
use function Psl\Type\non_empty_string;
use function Psl\Type\optional;
use function Psl\Type\shape;
use function Psl\Type\union;
use function Psl\Type\vec;

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
        try {
            $nameShape = dict(
                non_empty_string(),
                union(non_empty_string(), vec(non_empty_string())),
            );
            $fields = shape([
                'subject' => $nameShape,
                'issuer' => $nameShape,
                'serialNumber' => non_empty_string(),
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

        return new CertificateInfo(
            DistinguishedName::fromStructured($fields['subject']),
            DistinguishedName::fromStructured($fields['issuer']),
            (new SerialNumber())->toDecimal($fields['serialNumber']),
            new ValidityWindow(
                Timestamp::fromParts($fields['validFrom_time_t']),
                Timestamp::fromParts($fields['validTo_time_t']),
            ),
            $fields['extensions']['subjectKeyIdentifier'] ?? null,
            $fields['extensions']['keyUsage'] ?? null,
            $fingerprint,
        );
    }
}
