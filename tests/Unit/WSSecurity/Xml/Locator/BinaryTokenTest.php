<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Xml\Locator;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\BinaryToken;
use VeeWee\Xml\Dom\Document;

final class BinaryTokenTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    private function certificate(): Certificate
    {
        return Certificate::fromFile(FIXTURE_DIR.'/certificates/wsse-client-x509.pem');
    }

    public function test_it_returns_the_id_of_the_token_carrying_the_certificate(): void
    {
        $document = $this->envelope($this->token('the-token', $this->certificate()->toBase64Der()));

        $id = (new BinaryToken())->locate($this->securityHeader($document), $this->certificate());

        static::assertSame('the-token', $id);
    }

    public function test_it_refuses_when_no_token_carries_the_certificate(): void
    {
        $document = $this->envelope($this->token('other', base64_encode('not-the-certificate')));

        $this->expectException(WsseHeaderException::class);
        (new BinaryToken())->locate($this->securityHeader($document), $this->certificate());
    }

    public function test_it_does_not_look_outside_the_header_it_was_given(): void
    {
        // The locator is handed the header to search rather than sweeping the whole document, so a matching
        // token sitting elsewhere in the envelope is not a candidate.
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header><wsse:Security/></soap:Header>'
            .'<soap:Body>'.$this->token('elsewhere', $this->certificate()->toBase64Der()).'</soap:Body>'
            .'</soap:Envelope>'
        );

        $this->expectException(WsseHeaderException::class);
        (new BinaryToken())->locate($this->securityHeader($document), $this->certificate());
    }

    private function token(string $id, string $body): string
    {
        return '<wsse:BinarySecurityToken wsu:Id="'.$id.'">'.$body.'</wsse:BinarySecurityToken>';
    }

    private function envelope(string $securityChildren): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header><wsse:Security>'.$securityChildren.'</wsse:Security></soap:Header>'
            .'<soap:Body><data>x</data></soap:Body></soap:Envelope>'
        );
    }

    private function securityHeader(Document $document): Element
    {
        $element = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(self::WSSE, 'Security')->item(0);
        static::assertInstanceOf(Element::class, $element);

        return $element;
    }
}
