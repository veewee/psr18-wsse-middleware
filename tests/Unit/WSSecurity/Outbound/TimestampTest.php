<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use DateTimeImmutable;
use DateTimeZone;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Timestamp;
use VeeWee\Xml\Dom\Document;

final class TimestampTest extends OutboundTestCase
{
    private function bareEnvelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Body/></soap:Envelope>'
        );
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
