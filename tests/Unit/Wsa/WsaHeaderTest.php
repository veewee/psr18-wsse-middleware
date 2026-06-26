<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Wsa;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Wsa\MessageId;
use Soap\Psr18WsseMiddleware\Wsa\WsaHeader;
use Soap\Psr18WsseMiddleware\Wsa\WsaNamespace;
use VeeWee\Xml\Dom\Document;

final class WsaHeaderTest extends TestCase
{
    private const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';
    private const SOAP11 = 'http://schemas.xmlsoap.org/soap/envelope/';
    private const NS_2005 = 'http://www.w3.org/2005/08/addressing';
    private const NS_2004 = 'http://schemas.xmlsoap.org/ws/2004/08/addressing';

    private function emptyEnvelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Body/></soap:Envelope>'
        );
    }

    /** @return list<Element> */
    private function elements(Document $document, string $namespace, string $localName): array
    {
        $found = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS($namespace, $localName) as $element) {
            $found[] = $element;
        }

        return $found;
    }

    public function test_it_creates_the_header_and_emits_the_2005_addressing_elements(): void
    {
        $document = $this->emptyEnvelope();

        WsaHeader::create(WsaNamespace::W3c200508)
            ->withAction('urn:doSomething')
            ->withTo('https://example.test/endpoint')
            ->withMessageId(MessageId::generate())
            ->withReplyTo('https://example.test/reply')
            ->appendTo($document);

        $action = $this->elements($document, self::NS_2005, 'Action');
        static::assertCount(1, $action);
        static::assertSame('urn:doSomething', $action[0]->textContent);
        static::assertSame(self::NS_2005, $action[0]->namespaceURI);

        static::assertSame('https://example.test/endpoint', $this->elements($document, self::NS_2005, 'To')[0]->textContent);
        static::assertCount(1, $this->elements($document, self::NS_2005, 'MessageID'));

        $replyAddress = $this->elements($document, self::NS_2005, 'Address');
        static::assertCount(1, $replyAddress);
        static::assertSame('https://example.test/reply', $replyAddress[0]->textContent);

        // Address must be nested inside ReplyTo (canonical wsa:ReplyTo > wsa:Address)
        $parent = $replyAddress[0]->parentNode;
        static::assertInstanceOf(Element::class, $parent);
        static::assertSame('ReplyTo', $parent->localName);
        static::assertSame(self::NS_2005, $parent->namespaceURI);

        // header was created
        static::assertCount(1, $this->elements($document, self::SOAP12, 'Header'));
    }

    public function test_it_declares_the_wsa_namespace_once_on_the_header(): void
    {
        $document = $this->emptyEnvelope();

        WsaHeader::create(WsaNamespace::W3c200508)
            ->withAction('urn:doSomething')
            ->withTo('https://example.test/endpoint')
            ->withReplyTo('https://example.test/reply')
            ->appendTo($document);

        // The wsa namespace is declared a single time (on the header), not repeated on every block.
        static::assertSame(1, substr_count($document->toXmlString(), 'xmlns:wsa="'.self::NS_2005.'"'));
    }

    public function test_it_creates_the_header_for_a_soap_1_1_envelope(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP11.'"><soap:Body/></soap:Envelope>'
        );

        WsaHeader::create()->withAction('urn:x')->appendTo($document);

        static::assertCount(1, $this->elements($document, self::SOAP11, 'Header'));
        static::assertCount(1, $this->elements($document, self::NS_2005, 'Action'));
    }

    public function test_it_emits_the_2004_namespace_when_configured(): void
    {
        $document = $this->emptyEnvelope();

        WsaHeader::create(WsaNamespace::Submission200408)
            ->withAction('urn:doSomething')
            ->appendTo($document);

        static::assertCount(1, $this->elements($document, self::NS_2004, 'Action'));
        static::assertCount(0, $this->elements($document, self::NS_2005, 'Action'));
    }

    public function test_it_reuses_an_existing_header(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Header/><soap:Body/></soap:Envelope>'
        );

        WsaHeader::create()
            ->withAction('urn:x')
            ->appendTo($document);

        static::assertCount(1, $this->elements($document, self::SOAP12, 'Header'));
        static::assertCount(1, $this->elements($document, self::NS_2005, 'Action'));
    }
}
