<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use Psl\Type\Exception\CoercionException;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use function Psl\Type\dict;
use function Psl\Type\int;
use function Psl\Type\non_empty_string;
use function Psl\Type\nullish;
use function Psl\Type\shape;
use function Psl\Type\union;
use function Psl\Type\vec;

/**
 * The single reader of certificate fields: the values WSSE key-reference strategies embed in ds:KeyInfo
 * (subject key identifier, issuer and serial, thumbprint) and the fields trust verification needs (subject
 * name, validity window, key usage). All reads go through OpenSslCall so the single ext-openssl boundary stays
 * inside the OpenSSL namespace and the callers remain free of raw openssl_* calls.
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
        $hex = $this->parse($certificate)['extensions']['subjectKeyIdentifier'] ?? null;
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
            'issuerName' => $this->issuerName($info['issuer']),
            'serialNumber' => $this->serialNumber($info['serialNumber']),
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
     * The certificate's subject distinguished name, as openssl reports it. Used as the human-readable signer
     * identity once a chain is trusted.
     *
     * @return non-empty-string
     *
     * @throws CryptoOperationFailed when the certificate cannot be read
     */
    public function subjectName(Certificate $certificate): string
    {
        return $this->parse($certificate)['name'];
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
        $info = $this->parse($certificate);

        return ['from' => $info['validFrom_time_t'], 'to' => $info['validTo_time_t']];
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
        return $this->parse($certificate)['extensions']['keyUsage'] ?? null;
    }

    /**
     * Reads the identifying and trust fields out of openssl_x509_parse's untyped array. coerce() keeps the fields
     * modelled here typed and drops the rest; a CoercionException means a required field is absent, i.e. the
     * certificate is unparseable. The extensions are optional (present only when the cert carries them).
     *
     * @return array{
     *     name: non-empty-string,
     *     serialNumber: non-empty-string,
     *     issuer: array<non-empty-string, non-empty-string|list<non-empty-string>>,
     *     validFrom_time_t: int,
     *     validTo_time_t: int,
     *     extensions: array{subjectKeyIdentifier: non-empty-string|null, keyUsage: non-empty-string|null}|null
     * }
     */
    private function parse(Certificate $certificate): array
    {
        try {
            return shape([
                'name' => non_empty_string(),
                'serialNumber' => non_empty_string(),
                'issuer' => dict(
                    non_empty_string(),
                    union(non_empty_string(), vec(non_empty_string())),
                ),
                'validFrom_time_t' => int(),
                'validTo_time_t' => int(),
                'extensions' => nullish(shape([
                    'subjectKeyIdentifier' => nullish(non_empty_string()),
                    'keyUsage' => nullish(non_empty_string()),
                ])),
            ])->coerce(OpenSslCall::run(
                static fn () => openssl_x509_parse($certificate->contents()),
                'read the certificate',
            ));
        } catch (OpenSslException | CoercionException) {
            throw CryptoOperationFailed::unreadableCertificate();
        }
    }

    /**
     * Renders the issuer distinguished name in RFC 2253 form: comma-separated Type=Value relative names with the
     * most-specific name first, which reverses the order openssl reports. Multi-valued relative names are joined
     * with a plus sign, and the characters RFC 2253 reserves are escaped.
     *
     * @param array<non-empty-string, non-empty-string|list<non-empty-string>> $issuer
     *
     * @return non-empty-string
     */
    private function issuerName(array $issuer): string
    {
        $relativeNames = [];
        foreach ($issuer as $type => $value) {
            $values = is_array($value) ? $value : [$value];
            $pairs = [];
            foreach ($values as $single) {
                $pairs[] = $type . '=' . $this->escapeDistinguishedNameValue($single);
            }

            $relativeNames[] = implode('+', $pairs);
        }

        $name = implode(',', array_reverse($relativeNames));
        if ($name === '') {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return $name;
    }

    /**
     * Escapes the characters RFC 2253 reserves in an attribute value: the structural separators anywhere in the
     * value, a leading space or number sign, and a trailing space.
     */
    private function escapeDistinguishedNameValue(string $value): string
    {
        $escaped = str_replace(
            ['\\', ',', '+', '"', '<', '>', ';'],
            ['\\\\', '\\,', '\\+', '\\"', '\\<', '\\>', '\\;'],
            $value,
        );

        if (str_starts_with($escaped, ' ') || str_starts_with($escaped, '#')) {
            $escaped = '\\' . $escaped;
        }

        if (str_ends_with($escaped, ' ')) {
            $escaped = substr($escaped, 0, -1) . '\\ ';
        }

        return $escaped;
    }

    /**
     * Normalises the serial number to a decimal integer string. openssl reports the serial in decimal on this
     * build, but other builds report hexadecimal; both are accepted and serials larger than the platform integer
     * range are converted with arbitrary precision.
     *
     * @param non-empty-string $serialNumber
     *
     * @return non-empty-string
     */
    private function serialNumber(string $serialNumber): string
    {
        if (preg_match('/^\d+$/', $serialNumber) === 1) {
            return $serialNumber;
        }

        $hex = str_starts_with($serialNumber, '0x') ? substr($serialNumber, 2) : $serialNumber;
        if ($hex === '' || preg_match('/^[0-9A-Fa-f]+$/', $hex) !== 1) {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        $decimal = $this->hexToDecimal($hex);
        if ($decimal === '') {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return $decimal;
    }

    /**
     * Converts a hexadecimal string to its decimal representation with arbitrary precision, since serial numbers
     * routinely exceed the platform integer range.
     */
    private function hexToDecimal(string $hex): string
    {
        if (extension_loaded('gmp')) {
            return gmp_strval(gmp_init($hex, 16), 10);
        }

        if (extension_loaded('bcmath')) {
            $decimal = '0';
            foreach (str_split($hex) as $digit) {
                $decimal = bcadd(bcmul($decimal, '16'), (string) hexdec($digit));
            }

            return $decimal;
        }

        $decimal = [0];
        foreach (str_split($hex) as $digit) {
            $carry = (int) hexdec($digit);
            foreach ($decimal as $position => $value) {
                $value = $value * 16 + $carry;
                $decimal[$position] = $value % 10;
                $carry = intdiv($value, 10);
            }

            while ($carry > 0) {
                $decimal[] = $carry % 10;
                $carry = intdiv($carry, 10);
            }
        }

        return implode('', array_reverse(array_map(strval(...), $decimal)));
    }
}
