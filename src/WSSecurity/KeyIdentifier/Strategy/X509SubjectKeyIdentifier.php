<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy;

use Dom\Element;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateFieldExtractor;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;

/**
 * References the key by the certificate's Subject Key Identifier extension. The result is
 * ds:KeyInfo > wsse:SecurityTokenReference > wsse:KeyIdentifier carrying the base64-encoded SKI bytes.
 */
final class X509SubjectKeyIdentifier implements KeyIdentifierInterface
{
    private const VALUE_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier';
    private const ENCODING_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    public function __construct(
        private CertificateFieldExtractor $extractor,
    ) {
    }

    public function apply(Document $document, Certificate $certificate): Element
    {
        $encoded = $this->extractor->subjectKeyIdentifier($certificate);
        $reference = SecurityTokenReference::keyIdentifier($encoded, self::VALUE_TYPE, self::ENCODING_TYPE)
            ->build($document);

        return $document->map(namespaced_element(
            WsseNamespace::Ds->value,
            WsseNamespace::Ds->qualify('KeyInfo'),
            children(static fn (): Element => $reference),
        ));
    }
}
