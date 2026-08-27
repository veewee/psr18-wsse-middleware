<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound\KeyReference;

use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\SamlAssertionKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\SamlVersion;

final class SamlAssertionKeyIdentifierTest extends KeyIdentifierTestCase
{
    private const VALUE_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID';
    private const VALUE_TYPE_20 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID';
    private const TOKEN_TYPE_11 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1';
    private const TOKEN_TYPE_20 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0';

    public function test_it_emits_a_key_identifier_with_the_assertion_id(): void
    {
        $document = $this->document();

        $keyInfo = (new SamlAssertionKeyIdentifier('_assertion-123', SamlVersion::Saml11))
            ->apply($document);

        static::assertSame('KeyInfo', $keyInfo->localName);
        static::assertSame(self::DS, $keyInfo->namespaceURI);

        $str = $this->firstChildElement($keyInfo);
        static::assertSame('SecurityTokenReference', $str->localName);
        static::assertSame(self::WSSE, $str->namespaceURI);

        $keyIdentifier = $this->firstChildElement($str);
        static::assertSame('KeyIdentifier', $keyIdentifier->localName);
        static::assertSame(self::WSSE, $keyIdentifier->namespaceURI);
        static::assertSame(self::VALUE_TYPE, $keyIdentifier->getAttribute('ValueType'));
        static::assertSame('_assertion-123', $keyIdentifier->textContent);
    }

    public function test_it_does_not_carry_an_encoding_type(): void
    {
        $keyInfo = (new SamlAssertionKeyIdentifier('_assertion-123', SamlVersion::Saml11))
            ->apply($this->document());

        $keyIdentifier = $this->firstChildElement($this->firstChildElement($keyInfo));
        static::assertFalse($keyIdentifier->hasAttribute('EncodingType'));
    }

    public function test_a_saml_20_assertion_uses_the_1_1_profile_value_type(): void
    {
        // The SAML Token Profile gives 2.0 its own ValueType and requires a wsse11:TokenType naming the
        // version; the 1.0-profile SAMLAssertionID describes a 1.1 assertion, not a 2.0 one.
        $document = $this->document();

        $keyInfo = (new SamlAssertionKeyIdentifier('_assertion-123', SamlVersion::Saml20))
            ->apply($document);

        $str = $this->firstChildElement($keyInfo);
        static::assertSame(self::TOKEN_TYPE_20, $str->getAttributeNS(self::WSSE11, 'TokenType'));

        $keyIdentifier = $this->firstChildElement($str);
        static::assertSame(self::VALUE_TYPE_20, $keyIdentifier->getAttribute('ValueType'));
        static::assertSame('_assertion-123', $keyIdentifier->textContent);
    }

    public function test_a_saml_11_assertion_keeps_its_value_type_and_names_its_version(): void
    {
        $document = $this->document();

        $keyInfo = (new SamlAssertionKeyIdentifier('_assertion-123', SamlVersion::Saml11))
            ->apply($document);

        $str = $this->firstChildElement($keyInfo);
        static::assertSame(self::TOKEN_TYPE_11, $str->getAttributeNS(self::WSSE11, 'TokenType'));
        static::assertSame(self::VALUE_TYPE, $this->firstChildElement($str)->getAttribute('ValueType'));
    }
}
