<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy;

use Dom\Element;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateFieldExtractor;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * References the key by the certificate's issuer distinguished name and serial number. The result is a raw
 * ds:KeyInfo > ds:X509Data > ds:X509IssuerSerial; the X.509 token profile allows this form directly under
 * ds:KeyInfo, so no wsse:SecurityTokenReference wrapper is used.
 */
final class IssuerSerialKeyIdentifier implements KeyIdentifierInterface
{
    public function __construct(
        private CertificateFieldExtractor $extractor,
    ) {
    }

    public function apply(Document $document, Certificate $certificate): Element
    {
        $issuerSerial = $this->extractor->issuerSerial($certificate);

        return $document->map(namespaced_element(
            WsseNamespace::Ds->value,
            WsseNamespace::Ds->qualify('KeyInfo'),
            children(namespaced_element(
                WsseNamespace::Ds->value,
                WsseNamespace::Ds->qualify('X509Data'),
                children(namespaced_element(
                    WsseNamespace::Ds->value,
                    WsseNamespace::Ds->qualify('X509IssuerSerial'),
                    children(
                        namespaced_element(
                            WsseNamespace::Ds->value,
                            WsseNamespace::Ds->qualify('X509IssuerName'),
                            value($issuerSerial['issuerName']),
                        ),
                        namespaced_element(
                            WsseNamespace::Ds->value,
                            WsseNamespace::Ds->qualify('X509SerialNumber'),
                            value($issuerSerial['serialNumber']),
                        ),
                    ),
                )),
            )),
        ));
    }
}
