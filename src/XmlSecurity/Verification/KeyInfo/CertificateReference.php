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
    public const FORM_KEY_IDENTIFIER = 'keyIdentifier';
    public const FORM_ISSUER_SERIAL = 'issuerSerial';

    /**
     * @param self::FORM_* $form
     */
    private function __construct(
        public readonly string $form,
        public readonly string $base64Der = '',
        public readonly string $valueType = '',
        public readonly string $reference = '',
        public readonly string $issuerName = '',
        public readonly string $serialNumber = '',
    ) {
    }

    public static function carried(string $base64Der): self
    {
        return new self(self::FORM_CARRIED, base64Der: $base64Der);
    }

    public static function keyIdentifier(string $valueType, string $reference): self
    {
        return new self(self::FORM_KEY_IDENTIFIER, valueType: $valueType, reference: $reference);
    }

    public static function issuerSerial(string $issuerName, string $serialNumber): self
    {
        return new self(self::FORM_ISSUER_SERIAL, issuerName: $issuerName, serialNumber: $serialNumber);
    }
}
