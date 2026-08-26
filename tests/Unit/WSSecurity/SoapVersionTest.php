<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use VeeWee\Xml\Dom\Document;

final class SoapVersionTest extends TestCase
{
    private const SOAP11 = 'http://schemas.xmlsoap.org/soap/envelope/';
    private const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';

    public function test_it_detects_soap_11_from_a_document(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP11.'"><soap:Body/></soap:Envelope>'
        );

        static::assertSame(SoapVersion::Soap11, SoapVersion::fromDocument($document));
    }

    public function test_it_detects_soap_12_from_a_document(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Body/></soap:Envelope>'
        );

        static::assertSame(SoapVersion::Soap12, SoapVersion::fromDocument($document));
    }

    public function test_it_throws_on_a_non_soap_document(): void
    {
        $document = Document::fromXmlString('<root xmlns="urn:not-soap"/>');

        $this->expectException(WsseHeaderException::class);
        SoapVersion::fromDocument($document);
    }

    public function test_it_exposes_the_envelope_namespace(): void
    {
        static::assertSame(self::SOAP11, SoapVersion::Soap11->envelopeNamespace());
        static::assertSame(self::SOAP12, SoapVersion::Soap12->envelopeNamespace());
    }

    public function test_it_names_actor_for_soap_11_and_role_for_soap_12(): void
    {
        static::assertSame('actor', SoapVersion::Soap11->actorOrRoleName());
        static::assertSame('role', SoapVersion::Soap12->actorOrRoleName());
    }
}
