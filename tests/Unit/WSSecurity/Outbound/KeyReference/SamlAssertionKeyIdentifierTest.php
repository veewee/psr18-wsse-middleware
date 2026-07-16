<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound\KeyReference;

use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\SamlAssertionKeyIdentifier;

final class SamlAssertionKeyIdentifierTest extends KeyIdentifierTestCase
{
    private const VALUE_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID';

    public function test_it_emits_a_key_identifier_with_the_assertion_id(): void
    {
        $document = $this->document();

        $keyInfo = (new SamlAssertionKeyIdentifier('_assertion-123'))
            ->apply($document, $this->certificate());

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
        $keyInfo = (new SamlAssertionKeyIdentifier('_assertion-123'))
            ->apply($this->document(), $this->certificate());

        $keyIdentifier = $this->firstChildElement($this->firstChildElement($keyInfo));
        static::assertFalse($keyIdentifier->hasAttribute('EncodingType'));
    }
}
