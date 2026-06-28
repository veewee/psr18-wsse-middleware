<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Parser;

use Psl\Type\Exception\CoercionException;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use function Psl\Type\dict;
use function Psl\Type\int;
use function Psl\Type\non_empty_string;
use function Psl\Type\optional;
use function Psl\Type\shape;
use function Psl\Type\union;
use function Psl\Type\vec;

/**
 * The single reader of a certificate's fields. One instance runs the ext-openssl boundary exactly once: the
 * structured field parse and the fingerprint hash. Every other certificate field unit consumes the typed
 * getters here rather than touching openssl_* itself, so the boundary stays inside the OpenSSL namespace.
 */
final readonly class ParsedCertificate
{
    /**
     * @param array{
     *     name: non-empty-string,
     *     serialNumber: non-empty-string,
     *     issuer: array<non-empty-string, non-empty-string|list<non-empty-string>>,
     *     validFrom_time_t: int,
     *     validTo_time_t: int,
     *     extensions?: array{subjectKeyIdentifier?: non-empty-string, keyUsage?: non-empty-string}
     * } $fields
     * @param non-empty-string $sha1Fingerprint
     */
    private function __construct(
        private array $fields,
        private string $sha1Fingerprint,
    ) {
    }

    /**
     * Runs the structured parse and the fingerprint hash, coercing the untyped parse result into a typed
     * shape: coerce() keeps the modelled fields typed and drops the rest. A failure of either boundary call,
     * or an absent required field, means the certificate is unparseable. The extensions are optional, present
     * only when the certificate carries them.
     *
     * @throws CryptoOperationFailed when the certificate cannot be read
     */
    public static function fromCertificate(Certificate $certificate): self
    {
        try {
            $fields = shape([
                'name' => non_empty_string(),
                'serialNumber' => non_empty_string(),
                'issuer' => dict(
                    non_empty_string(),
                    union(non_empty_string(), vec(non_empty_string())),
                ),
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

        if ($fingerprint === '') {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return new self($fields, $fingerprint);
    }

    /**
     * @return non-empty-string
     */
    public function subjectName(): string
    {
        return $this->fields['name'];
    }

    /**
     * @return array<non-empty-string, non-empty-string|list<non-empty-string>>
     */
    public function issuer(): array
    {
        return $this->fields['issuer'];
    }

    /**
     * The serial number exactly as openssl reports it, before any decimal normalisation.
     *
     * @return non-empty-string
     */
    public function serialNumberRaw(): string
    {
        return $this->fields['serialNumber'];
    }

    public function validFrom(): int
    {
        return $this->fields['validFrom_time_t'];
    }

    public function validTo(): int
    {
        return $this->fields['validTo_time_t'];
    }

    /**
     * The Subject Key Identifier extension value in its colon-separated hex form, or null when the
     * certificate carries no such extension.
     *
     * @return non-empty-string|null
     */
    public function subjectKeyIdentifierHex(): ?string
    {
        return $this->fields['extensions']['subjectKeyIdentifier'] ?? null;
    }

    /**
     * @return non-empty-string|null
     */
    public function keyUsage(): ?string
    {
        return $this->fields['extensions']['keyUsage'] ?? null;
    }

    /**
     * The raw SHA-1 fingerprint bytes of the DER-encoded certificate.
     *
     * @return non-empty-string
     */
    public function sha1Fingerprint(): string
    {
        return $this->sha1Fingerprint;
    }
}
