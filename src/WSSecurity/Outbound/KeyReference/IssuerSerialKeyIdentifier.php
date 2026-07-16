<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;

/**
 * References the key by the certificate's issuer distinguished name and serial number. The result is
 * ds:KeyInfo > wsse:SecurityTokenReference > ds:X509Data > ds:X509IssuerSerial. The WS-Security X.509 token
 * profile requires the issuer-serial reference to sit inside a wsse:SecurityTokenReference for interop.
 */
final class IssuerSerialKeyIdentifier implements KeyIdentifierInterface
{
    public function apply(Document $document, Certificate $certificate): Element
    {
        $issuerSerial = $certificate->info()->issuerSerial();

        return SecurityTokenReference::x509IssuerSerial($issuerSerial->issuer->toString(), $issuerSerial->serialNumber->toString())
            ->buildKeyInfo($document);
    }
}
