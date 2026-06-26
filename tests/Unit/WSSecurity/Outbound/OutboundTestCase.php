<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use VeeWee\Xml\Dom\Document;

/**
 * Shared scaffolding for the outbound block tests: a minimal SOAP 1.2 envelope, a per-message context,
 * and namespace-aware element lookups so each test asserts on the produced DOM without repeating the
 * traversal boilerplate.
 */
abstract class OutboundTestCase extends TestCase
{
    protected const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';
    protected const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    protected const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    protected function envelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Header/><soap:Body/></soap:Envelope>'
        );
    }

    protected function context(Document $document): WsseContext
    {
        return new WsseContext($document, SoapVersion::Soap12);
    }

    /** @return list<Element> */
    protected function elements(Document $document, string $namespace, string $localName): array
    {
        $found = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS($namespace, $localName) as $element) {
            $found[] = $element;
        }

        return $found;
    }

    protected function only(Document $document, string $namespace, string $localName): Element
    {
        $elements = $this->elements($document, $namespace, $localName);
        static::assertCount(1, $elements);

        return $elements[0];
    }
}
