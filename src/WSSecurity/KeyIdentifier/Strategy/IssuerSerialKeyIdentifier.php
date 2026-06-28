<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy;

use Dom\Element;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateFieldExtractor;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;

/**
 * References the key by the certificate's issuer distinguished name and serial number. The result is
 * ds:KeyInfo > wsse:SecurityTokenReference > ds:X509Data > ds:X509IssuerSerial. The WS-Security X.509 token
 * profile requires the issuer-serial reference to sit inside a wsse:SecurityTokenReference for interop.
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
        $reference = SecurityTokenReference::x509IssuerSerial($issuerSerial['issuerName'], $issuerSerial['serialNumber'])
            ->build($document);

        return $document->map(namespaced_element(
            Namespaces::Ds->value,
            Namespaces::Ds->qualify('KeyInfo'),
            children(static fn (): Element => $reference),
        ));
    }
}
