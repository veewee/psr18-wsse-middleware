<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy;

use Dom\Element;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateFieldExtractor;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;

/**
 * References the key by the SHA-1 fingerprint of the certificate, expressed as a wsse11:KeyIdentifier. The
 * result is ds:KeyInfo > wsse:SecurityTokenReference > wsse11:KeyIdentifier with the base64-encoded fingerprint.
 * The KeyIdentifier itself lives in the WSSE 1.1 namespace while the enclosing reference stays in WSSE 1.0.
 */
final class ThumbprintKeyIdentifier implements KeyIdentifierInterface
{
    public function __construct(
        private CertificateFieldExtractor $extractor,
    ) {
    }

    public function apply(Document $document, Certificate $certificate): Element
    {
        $encoded = $this->extractor->thumbprintSha1($certificate);

        return SecurityTokenReference::thumbprint($encoded)->buildKeyInfo($document);
    }
}
