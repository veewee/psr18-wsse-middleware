<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy;

use Dom\Element;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateFieldExtractor;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * References the key by the SHA-1 fingerprint of the certificate, expressed as a wsse11:KeyIdentifier. The
 * result is ds:KeyInfo > wsse:SecurityTokenReference > wsse11:KeyIdentifier with the base64-encoded fingerprint.
 * The KeyIdentifier itself lives in the WSSE 1.1 namespace while the enclosing reference stays in WSSE 1.0.
 */
final class ThumbprintKeyIdentifier implements KeyIdentifierInterface
{
    private const VALUE_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1';
    private const ENCODING_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    public function __construct(
        private CertificateFieldExtractor $extractor,
    ) {
    }

    public function apply(Document $document, Certificate $certificate): Element
    {
        $encoded = $this->extractor->thumbprintSha1($certificate);

        return $document->map(namespaced_element(
            Namespaces::Ds->value,
            Namespaces::Ds->qualify('KeyInfo'),
            children(namespaced_element(
                Namespaces::Wsse->value,
                Namespaces::Wsse->qualify('SecurityTokenReference'),
                children(namespaced_element(
                    Namespaces::Wsse11->value,
                    Namespaces::Wsse11->qualify('KeyIdentifier'),
                    attribute('ValueType', self::VALUE_TYPE),
                    attribute('EncodingType', self::ENCODING_TYPE),
                    value($encoded),
                )),
            )),
        ));
    }
}
