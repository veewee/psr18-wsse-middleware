<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity;

use LogicException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\PartKind;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\Xml\QualifiedName;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionMode;
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

    public function test_timestamp_is_an_element_shortcut_for_the_wsu_timestamp(): void
    {
        $part = Part::timestamp();

        static::assertSame(PartKind::Element, $part->kind());
        static::assertSame('http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd', $part->namespace());
        static::assertSame('Timestamp', $part->localName());
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
        // The Body lowers to its position in the envelope, not to its name alone.
        static::assertTrue(
            Part::body()->toTarget(SoapVersion::Soap11)->equals(self::bodyPath('http://schemas.xmlsoap.org/soap/envelope/')),
        );
        static::assertTrue(
            Part::body()->toTarget(SoapVersion::Soap12)->equals(self::bodyPath('http://www.w3.org/2003/05/soap-envelope')),
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

    public function test_username_token_shortcut_lowers_to_the_wsse_username_token_element(): void
    {
        static::assertTrue(
            Part::usernameToken()->toTarget(SoapVersion::Soap12)->equals(Target::element(
                'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
                'UsernameToken',
            )),
        );
    }

    public function test_binary_security_token_shortcut_lowers_to_the_wsse_bst_element(): void
    {
        static::assertTrue(
            Part::binarySecurityToken()->toTarget(SoapVersion::Soap12)->equals(Target::element(
                'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
                'BinarySecurityToken',
            )),
        );
    }

    public function test_security_header_contents_is_a_dynamic_part(): void
    {
        static::assertSame(PartKind::SecurityHeaderContents, Part::securityHeaderContents()->kind());
    }

    public function test_soap_headers_is_a_dynamic_part(): void
    {
        static::assertSame(PartKind::SoapHeaders, Part::soapHeaders()->kind());
    }

    public function test_a_dynamic_part_cannot_lower_to_a_single_target(): void
    {
        $this->expectException(LogicException::class);

        Part::securityHeaderContents()->toTarget(SoapVersion::Soap12);
    }

    public function test_soap_headers_cannot_lower_to_a_single_target(): void
    {
        $this->expectException(LogicException::class);

        Part::soapHeaders()->toTarget(SoapVersion::Soap12);
    }

    public function test_the_body_is_encrypted_as_content(): void
    {
        static::assertSame(EncryptionMode::Content, Part::body()->encryptionMode());
    }

    public function test_targeted_parts_are_encrypted_as_element(): void
    {
        static::assertSame(EncryptionMode::Element, Part::element('urn:a', 'X')->encryptionMode());
        static::assertSame(EncryptionMode::Element, Part::byId('X')->encryptionMode());
        static::assertSame(EncryptionMode::Element, Part::usernameToken()->encryptionMode());
        static::assertSame(EncryptionMode::Element, Part::binarySecurityToken()->encryptionMode());
        static::assertSame(EncryptionMode::Element, Part::timestamp()->encryptionMode());
    }

    public function test_signing_only_dynamic_parts_have_no_encryption_mode(): void
    {
        static::assertNull(Part::securityHeaderContents()->encryptionMode());
        static::assertNull(Part::soapHeaders()->encryptionMode());
    }

    public function test_the_encryption_mode_can_be_overridden(): void
    {
        $part = Part::element('urn:a', 'X')->withEncryptionMode(EncryptionMode::Content);

        static::assertSame(EncryptionMode::Content, $part->encryptionMode());
    }

    public function test_the_encryption_mode_is_part_of_equality(): void
    {
        $element = Part::element('urn:a', 'X');

        static::assertFalse($element->equals($element->withEncryptionMode(EncryptionMode::Content)));
    }
    private static function bodyPath(string $envelopeNamespace): Target
    {
        return Target::path(
            new QualifiedName($envelopeNamespace, 'Envelope'),
            new QualifiedName($envelopeNamespace, 'Body'),
        );
    }
}
