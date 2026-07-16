<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Default;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\KeyInfoBuilder;
use VeeWee\Xml\Dom\Document;

final class KeyInfoBuilderTest extends TestCase
{
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

    public function test_it_returns_the_key_info_produced_by_the_strategy(): void
    {
        $keyInfo = (new KeyInfoBuilder())->build(
            Document::fromXmlString('<root/>'),
            new DirectReferenceKeyIdentifier('token-1', 'urn:value-type'),
            new Certificate('cert'),
        );

        static::assertSame('KeyInfo', $keyInfo->localName);
        static::assertSame(self::DS, $keyInfo->namespaceURI);
    }

    public function test_it_passes_the_document_and_certificate_to_the_strategy(): void
    {
        $document = Document::fromXmlString('<root/>');
        $certificate = new Certificate('cert');

        $strategy = new class implements KeyIdentifier {
            public ?Document $seenDocument = null;
            public ?Certificate $seenCertificate = null;

            public function apply(Document $document, Certificate $certificate): Element
            {
                $this->seenDocument = $document;
                $this->seenCertificate = $certificate;

                return $document->map(static fn (\Dom\XMLDocument $d): Element => $d->createElementNS(
                    'http://www.w3.org/2000/09/xmldsig#',
                    'ds:KeyInfo',
                ));
            }
        };

        (new KeyInfoBuilder())->build($document, $strategy, $certificate);

        static::assertSame($document, $strategy->seenDocument);
        static::assertSame($certificate, $strategy->seenCertificate);
    }
}
