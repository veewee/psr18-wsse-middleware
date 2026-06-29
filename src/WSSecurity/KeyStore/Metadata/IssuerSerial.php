<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata;

/**
 * A certificate's issuer distinguished name together with its serial number in decimal form, the pair a
 * ds:X509IssuerSerial reference carries.
 */
final readonly class IssuerSerial
{
    /**
     * @param non-empty-string $serialNumber decimal serial number
     */
    public function __construct(
        public DistinguishedName $issuer,
        public string $serialNumber,
    ) {
    }
}
