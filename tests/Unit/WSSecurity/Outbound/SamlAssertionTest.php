<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Dom\Element;
use LogicException;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\SamlAssertion;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\SamlVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Timestamp;

final class SamlAssertionTest extends OutboundTestCase
{
    private const SAML11 = 'urn:oasis:names:tc:SAML:1.0:assertion';
    private const SAML20 = 'urn:oasis:names:tc:SAML:2.0:assertion';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

    private function saml11(string $id = 'SamlAssertion-11', bool $withId = true): string
    {
        $idAttr = $withId ? ' AssertionID="'.$id.'"' : '';

        return '<saml:Assertion xmlns:saml="'.self::SAML11.'"'.$idAttr.' MajorVersion="1" MinorVersion="1">'
            .'<saml:Conditions/></saml:Assertion>';
    }

    private function saml20(string $id = 'SamlAssertion-20', bool $withId = true): string
    {
        $idAttr = $withId ? ' ID="'.$id.'"' : '';

        return '<saml2:Assertion xmlns:saml2="'.self::SAML20.'"'.$idAttr.' Version="2.0">'
            .'<saml2:Issuer>issuer</saml2:Issuer></saml2:Assertion>';
    }

    public function test_it_imports_a_saml_11_assertion_into_the_security_header(): void
    {
        $document = $this->envelope();

        (new SamlAssertion($this->saml11(), SamlVersion::Saml11))($this->context($document));

        $security = $this->only($document, self::WSSE, 'Security');
        $assertion = $this->only($document, self::SAML11, 'Assertion');
        static::assertSame($security, $assertion->parentNode);
    }

    public function test_it_extracts_the_assertion_id_from_saml_11(): void
    {
        $document = $this->envelope();

        $block = new SamlAssertion($this->saml11('id-saml11-abc'), SamlVersion::Saml11);
        $block($this->context($document));

        static::assertSame('id-saml11-abc', $block->assertionId());
    }

    public function test_saml_11_throws_when_assertion_id_is_missing(): void
    {
        $document = $this->envelope();

        $this->expectException(WsseHeaderException::class);

        (new SamlAssertion($this->saml11(withId: false), SamlVersion::Saml11))($this->context($document));
    }

    public function test_saml_11_throws_on_namespace_mismatch(): void
    {
        $document = $this->envelope();

        $this->expectException(WsseHeaderException::class);

        (new SamlAssertion($this->saml20(), SamlVersion::Saml11))($this->context($document));
    }

    public function test_it_imports_a_saml_20_assertion_into_the_security_header(): void
    {
        $document = $this->envelope();

        (new SamlAssertion($this->saml20(), SamlVersion::Saml20))($this->context($document));

        $security = $this->only($document, self::WSSE, 'Security');
        $assertion = $this->only($document, self::SAML20, 'Assertion');
        static::assertSame($security, $assertion->parentNode);
    }

    public function test_it_extracts_the_assertion_id_from_saml_20(): void
    {
        $document = $this->envelope();

        $block = new SamlAssertion($this->saml20('id-saml20-xyz'), SamlVersion::Saml20);
        $block($this->context($document));

        static::assertSame('id-saml20-xyz', $block->assertionId());
    }

    public function test_saml_20_throws_when_id_attribute_is_missing(): void
    {
        $document = $this->envelope();

        $this->expectException(WsseHeaderException::class);

        (new SamlAssertion($this->saml20(withId: false), SamlVersion::Saml20))($this->context($document));
    }

    public function test_saml_20_throws_on_namespace_mismatch(): void
    {
        $document = $this->envelope();

        $this->expectException(WsseHeaderException::class);

        (new SamlAssertion($this->saml11(), SamlVersion::Saml20))($this->context($document));
    }

    public function test_a_doctype_in_the_assertion_is_rejected(): void
    {
        $document = $this->envelope();
        $malicious = '<?xml version="1.0"?>'
            .'<!DOCTYPE saml:Assertion [<!ENTITY xxe "pwned">]>'
            .'<saml:Assertion xmlns:saml="'.self::SAML11.'" AssertionID="evil">&xxe;</saml:Assertion>';

        $this->expectException(WsseHeaderException::class);

        (new SamlAssertion($malicious, SamlVersion::Saml11))($this->context($document));
    }

    public function test_malformed_assertion_xml_throws_cleanly(): void
    {
        $document = $this->envelope();

        $this->expectException(WsseHeaderException::class);

        (new SamlAssertion('<saml:Assertion>not closed', SamlVersion::Saml11))($this->context($document));
    }

    public function test_a_non_assertion_xml_document_throws(): void
    {
        $document = $this->envelope();
        $envelope = '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Body/></soap:Envelope>';

        $this->expectException(WsseHeaderException::class);

        (new SamlAssertion($envelope, SamlVersion::Saml20))($this->context($document));
    }

    public function test_a_signed_assertions_signature_survives_the_import(): void
    {
        $document = $this->envelope();
        $signed = '<saml2:Assertion xmlns:saml2="'.self::SAML20.'" ID="signed-1" Version="2.0">'
            .'<ds:Signature xmlns:ds="'.self::DS.'"><ds:SignatureValue>abc</ds:SignatureValue></ds:Signature>'
            .'</saml2:Assertion>';

        (new SamlAssertion($signed, SamlVersion::Saml20))($this->context($document));

        $signature = $this->only($document, self::DS, 'Signature');
        $assertion = $this->only($document, self::SAML20, 'Assertion');
        static::assertSame($assertion, $signature->parentNode);
        static::assertSame('abc', $signature->textContent);
    }

    public function test_assertion_namespace_declarations_are_preserved_after_import(): void
    {
        $document = $this->envelope();

        (new SamlAssertion($this->saml20('ns-1'), SamlVersion::Saml20))($this->context($document));

        $assertion = $this->only($document, self::SAML20, 'Assertion');
        static::assertSame(self::SAML20, $assertion->namespaceURI);
    }

    public function test_assertion_id_throws_before_invoke(): void
    {
        $block = new SamlAssertion($this->saml20(), SamlVersion::Saml20);

        $this->expectException(LogicException::class);

        $block->assertionId();
    }

    public function test_it_creates_the_security_header_when_absent(): void
    {
        $document = $this->envelope();

        (new SamlAssertion($this->saml20(), SamlVersion::Saml20))($this->context($document));

        $this->only($document, self::WSSE, 'Security');
        $this->only($document, self::SAML20, 'Assertion');
    }

    public function test_the_assertion_follows_a_timestamp_in_the_security_header(): void
    {
        $document = $this->envelope();
        $context = $this->context($document);

        (new SamlAssertion($this->saml20(), SamlVersion::Saml20))($context);
        (new Timestamp())($context);

        $security = $this->only($document, self::WSSE, 'Security');
        $order = [];
        foreach ($security->childNodes as $child) {
            if ($child instanceof Element) {
                $order[] = $child->localName;
            }
        }

        static::assertSame(['Timestamp', 'Assertion'], $order);
    }
}
