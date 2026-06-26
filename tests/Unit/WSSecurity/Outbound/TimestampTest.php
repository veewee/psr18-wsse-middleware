<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use DateTimeImmutable;
use DateTimeZone;
use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Timestamp;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use VeeWee\Xml\Dom\Document;

final class TimestampTest extends TestCase
{
    private const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    private function envelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Header/><soap:Body/></soap:Envelope>'
        );
    }

    private function bareEnvelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Body/></soap:Envelope>'
        );
    }

    private function context(Document $document): WsseContext
    {
        return new WsseContext($document, SoapVersion::Soap12);
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

    private function only(Document $document, string $namespace, string $localName): Element
    {
        $elements = $this->elements($document, $namespace, $localName);
        static::assertCount(1, $elements);

        return $elements[0];
    }

    public function test_it_adds_a_timestamp_to_the_security_header(): void
    {
        $document = $this->envelope();

        (new Timestamp())($this->context($document));

        $security = $this->only($document, self::WSSE, 'Security');
        $timestamp = $this->only($document, self::WSU, 'Timestamp');
        static::assertSame($security, $timestamp->parentNode);
    }

    public function test_it_creates_the_security_header_when_absent(): void
    {
        $document = $this->bareEnvelope();

        (new Timestamp())($this->context($document));

        static::assertCount(1, $this->elements($document, self::WSSE, 'Security'));
        static::assertCount(1, $this->elements($document, self::WSU, 'Timestamp'));
    }

    public function test_created_is_utc_now(): void
    {
        $document = $this->envelope();

        (new Timestamp())($this->context($document));

        $created = $this->only($document, self::WSU, 'Created')->textContent;
        $parsed = new DateTimeImmutable($created);
        static::assertEqualsWithDelta(
            (new DateTimeImmutable('now', new DateTimeZone('UTC')))->getTimestamp(),
            $parsed->getTimestamp(),
            2,
        );
    }

    public function test_expires_is_created_plus_default_ttl(): void
    {
        $document = $this->envelope();

        (new Timestamp())($this->context($document));

        static::assertSame(300, $this->ttlDelta($document));
    }

    public function test_custom_ttl_is_applied(): void
    {
        $document = $this->envelope();

        (new Timestamp(600))($this->context($document));

        static::assertSame(600, $this->ttlDelta($document));
    }

    public function test_created_and_expires_use_millisecond_precision(): void
    {
        $document = $this->envelope();

        (new Timestamp())($this->context($document));

        $pattern = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/';
        static::assertMatchesRegularExpression($pattern, $this->only($document, self::WSU, 'Created')->textContent);
        static::assertMatchesRegularExpression($pattern, $this->only($document, self::WSU, 'Expires')->textContent);
    }

    public function test_the_timestamp_carries_a_minted_wsu_id(): void
    {
        $document = $this->envelope();

        (new Timestamp())($this->context($document));

        $id = $this->only($document, self::WSU, 'Timestamp')->getAttributeNS(self::WSU, 'Id');
        static::assertMatchesRegularExpression('/^id-[0-9a-f-]{36}$/', $id);
    }

    private function ttlDelta(Document $document): int
    {
        $created = new DateTimeImmutable($this->only($document, self::WSU, 'Created')->textContent);
        $expires = new DateTimeImmutable($this->only($document, self::WSU, 'Expires')->textContent);

        return $expires->getTimestamp() - $created->getTimestamp();
    }
}
