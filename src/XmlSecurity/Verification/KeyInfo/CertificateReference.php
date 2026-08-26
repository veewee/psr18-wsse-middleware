<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo;

/**
 * What ds:KeyInfo names about the signer certificate, as one of three forms the reader produces and the
 * orchestrator dispatches on. A carried reference holds the certificate bytes the message carries directly (a
 * BST or an inline ds:X509Certificate); a key-identifier reference names the certificate by Subject Key
 * Identifier or SHA-1 thumbprint; an issuer-serial reference names it by issuer DN and serial. The two
 * identifier forms carry no certificate and are resolved against the trust store.
 *
 * @psalm-immutable
 */
final readonly class CertificateReference
{
    public const FORM_CARRIED = 'carried';
    public const FORM_CARRIED_PATH = 'carriedPath';
    public const FORM_KEY_IDENTIFIER = 'keyIdentifier';
    public const FORM_ISSUER_SERIAL = 'issuerSerial';

    /**
     * @param self::FORM_*  $form
     * @param list<string>  $base64DerCertificates
     */
    private function __construct(
        public readonly string $form,
        public readonly array $base64DerCertificates = [],
        public readonly ?KeyIdentifierKind $kind = null,
        public readonly string $reference = '',
        public readonly string $issuerName = '',
        public readonly string $serialNumber = '',
    ) {
    }

    /**
     * A carried reference may hold a whole certification path, not just one certificate: XML-DSig allows
     * several ds:X509Certificate elements under one ds:X509Data, and a PKIPath token carries a chain too.
     */
    public static function carried(string ...$base64DerCertificates): self
    {
        return new self(self::FORM_CARRIED, base64DerCertificates: array_values($base64DerCertificates));
    }

    /**
     * A whole certification path carried as one PKIPath token body, which is a single base64 ASN.1 structure
     * rather than one entry per certificate. It stays undecoded here: this type reports what ds:KeyInfo says,
     * and unwrapping the path is the orchestrator's job so a malformed one fails at the uniform boundary.
     */
    public static function carriedPath(string $base64DerPath): self
    {
        return new self(self::FORM_CARRIED_PATH, base64DerCertificates: [$base64DerPath]);
    }

    public static function keyIdentifier(KeyIdentifierKind $kind, string $reference): self
    {
        return new self(self::FORM_KEY_IDENTIFIER, kind: $kind, reference: $reference);
    }

    public static function issuerSerial(string $issuerName, string $serialNumber): self
    {
        return new self(self::FORM_ISSUER_SERIAL, issuerName: $issuerName, serialNumber: $serialNumber);
    }
}
