<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Xml;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Xpath;
use VeeWee\Xml\Dom\Document;

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

    public function test_it_locates_the_security_header_on_soap_12(): void
    {
        $document = Document::fromXmlString($this->envelope(self::SOAP12));

        $security = $document->xpath(new Xpath($document))
            ->querySingle('/soap:Envelope/soap:Header/wsse:Security');

        static::assertSame('Security', $security->localName);
    }

    public function test_it_locates_the_security_header_on_soap_11(): void
    {
        $document = Document::fromXmlString($this->envelope(self::SOAP11));

        $security = $document->xpath(new Xpath($document))
            ->querySingle('/soap:Envelope/soap:Header/wsse:Security');

        static::assertSame('Security', $security->localName);
    }

    public function test_it_registers_wsu_ds_and_xenc_prefixes(): void
    {
        $document = Document::fromXmlString($this->envelope(self::SOAP12));
        $xpath = $document->xpath(new Xpath($document));

        static::assertSame('Timestamp', $xpath->querySingle('//wsu:Timestamp')->localName);
        static::assertSame('Signature', $xpath->querySingle('//ds:Signature')->localName);
        static::assertSame('EncryptedKey', $xpath->querySingle('//xenc:EncryptedKey')->localName);
    }
}
