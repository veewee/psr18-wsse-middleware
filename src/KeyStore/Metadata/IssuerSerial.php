<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore\Metadata;

/**
 * A certificate's issuer distinguished name together with its serial number, the pair a ds:X509IssuerSerial
 * reference carries.
 */
final readonly class IssuerSerial
{
    public function __construct(
        public DistinguishedName $issuer,
        public SerialNumber $serialNumber,
    ) {
    }
}
