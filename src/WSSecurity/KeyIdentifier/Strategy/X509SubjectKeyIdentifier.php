<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityEncodingType;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityValueType;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;

/**
 * References the key by the certificate's Subject Key Identifier extension. The result is
 * ds:KeyInfo > wsse:SecurityTokenReference > wsse:KeyIdentifier carrying the base64-encoded SKI bytes.
 */
final class X509SubjectKeyIdentifier implements KeyIdentifierInterface
{
    public function apply(Document $document, Certificate $certificate): Element
    {
        $encoded = $certificate->info()->subjectKeyIdentifier()->toBase64();

        return SecurityTokenReference::keyIdentifier(
            $encoded,
            WsSecurityValueType::X509SubjectKeyIdentifier->value,
            WsSecurityEncodingType::Base64Binary->value,
        )->buildKeyInfo($document);
    }
}
