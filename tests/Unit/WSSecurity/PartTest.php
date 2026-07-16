<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\PartKind;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;

final class PartTest extends TestCase
{
    public function test_body_part(): void
    {
        $part = Part::body();

        static::assertSame(PartKind::Body, $part->kind());
        static::assertNull($part->namespace());
        static::assertNull($part->localName());
        static::assertNull($part->id());
    }

    public function test_timestamp_part(): void
    {
        static::assertSame(PartKind::Timestamp, Part::timestamp()->kind());
    }

    public function test_element_part_carries_namespace_and_local_name(): void
    {
        $part = Part::element('urn:example', 'Body');

        static::assertSame(PartKind::Element, $part->kind());
        static::assertSame('urn:example', $part->namespace());
        static::assertSame('Body', $part->localName());
    }

    public function test_id_part_carries_the_id(): void
    {
        $part = Part::byId('TS-1');

        static::assertSame(PartKind::Id, $part->kind());
        static::assertSame('TS-1', $part->id());
    }

    public function test_parts_are_compared_by_value(): void
    {
        static::assertTrue(Part::body()->equals(Part::body()));
        static::assertTrue(Part::element('urn:a', 'X')->equals(Part::element('urn:a', 'X')));
        static::assertFalse(Part::body()->equals(Part::timestamp()));
        static::assertFalse(Part::element('urn:a', 'X')->equals(Part::element('urn:a', 'Y')));
        static::assertFalse(Part::byId('a')->equals(Part::byId('b')));
    }

    public function test_it_lowers_the_body_to_the_soap_envelope_body_of_the_version(): void
    {
        static::assertTrue(
            Part::body()->toTarget(SoapVersion::Soap11)
                ->equals(Target::element('http://schemas.xmlsoap.org/soap/envelope/', 'Body')),
        );
        static::assertTrue(
            Part::body()->toTarget(SoapVersion::Soap12)
                ->equals(Target::element('http://www.w3.org/2003/05/soap-envelope', 'Body')),
        );
    }

    public function test_it_lowers_the_timestamp_to_the_wsu_timestamp(): void
    {
        static::assertTrue(
            Part::timestamp()->toTarget(SoapVersion::Soap12)->equals(Target::element(
                'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
                'Timestamp',
            )),
        );
    }

    public function test_it_lowers_element_and_id_shortcuts_verbatim(): void
    {
        static::assertTrue(
            Part::element('urn:a', 'X')->toTarget(SoapVersion::Soap12)->equals(Target::element('urn:a', 'X')),
        );
        static::assertTrue(
            Part::byId('TS-1')->toTarget(SoapVersion::Soap12)->equals(Target::byId('TS-1')),
        );
    }
}
