<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Xml;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespaces;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\Xpath;
use VeeWee\Xml\Dom\Document;

/**
 * The configurator binds `soap` from the document itself and nothing else unless it is given. Which prefixes a
 * query may use is therefore the caller's declaration, not a package-wide list -- so the generic Xml layer never
 * has to name a specification layered above it.
 */
final class XpathTest extends TestCase
{
    private const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';
    private const SOAP11 = 'http://schemas.xmlsoap.org/soap/envelope/';

    private function envelope(string $soapNs): string
    {
        return <<<XML
        <soap:Envelope xmlns:soap="{$soapNs}">
          <soap:Header>
            <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
              <wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="TS-1"/>
              <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>
              <xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/>
            </wsse:Security>
          </soap:Header>
          <soap:Body/>
        </soap:Envelope>
        XML;
    }

    public function test_it_binds_soap_from_the_document_on_soap_12(): void
    {
        $document = Document::fromXmlString($this->envelope(self::SOAP12));

        $security = $document->xpath(new Xpath($document, $this->wsse()))
            ->querySingle('/soap:Envelope/soap:Header/wsse:Security');

        static::assertSame('Security', $security->localName);
    }

    public function test_it_binds_soap_from_the_document_on_soap_11(): void
    {
        $document = Document::fromXmlString($this->envelope(self::SOAP11));

        $security = $document->xpath(new Xpath($document, $this->wsse()))
            ->querySingle('/soap:Envelope/soap:Header/wsse:Security');

        static::assertSame('Security', $security->localName);
    }

    public function test_it_binds_every_prefix_it_is_given(): void
    {
        $document = Document::fromXmlString($this->envelope(self::SOAP12));
        $xpath = $document->xpath(new Xpath($document, [
            ...$this->wsse(),
            WsseNamespaces::Wsu->prefix() => WsseNamespaces::Wsu->uri(),
            Namespaces::Ds->prefix() => Namespaces::Ds->uri(),
            Namespaces::Xenc->prefix() => Namespaces::Xenc->uri(),
        ]));

        static::assertSame('Timestamp', $xpath->querySingle('//wsu:Timestamp')->localName);
        static::assertSame('Signature', $xpath->querySingle('//ds:Signature')->localName);
        static::assertSame('EncryptedKey', $xpath->querySingle('//xenc:EncryptedKey')->localName);
    }

    public function test_a_prefix_it_was_not_given_is_not_bound(): void
    {
        // The point of passing bindings per query: nothing is bound package-wide, so a layer cannot come to depend
        // on a prefix belonging to a specification it should not know about.
        $document = Document::fromXmlString($this->envelope(self::SOAP12));
        $xpath = $document->xpath(new Xpath($document, $this->wsse()));

        $this->expectException(RuntimeException::class);
        $xpath->querySingle('//wsu:Timestamp');
    }

    /**
     * @return array<non-empty-string, non-empty-string>
     */
    private function wsse(): array
    {
        return [WsseNamespaces::Wsse->prefix() => WsseNamespaces::Wsse->uri()];
    }
}
