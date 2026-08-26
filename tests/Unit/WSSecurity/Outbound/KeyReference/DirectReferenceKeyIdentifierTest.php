<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound\KeyReference;

use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\DirectReferenceKeyIdentifier;

final class DirectReferenceKeyIdentifierTest extends KeyIdentifierTestCase
{
    public function test_it_emits_a_key_info_reference_to_the_supplied_token_id(): void
    {
        $document = $this->document();
        $strategy = new DirectReferenceKeyIdentifier('token-1', 'urn:value-type');

        $keyInfo = $strategy->apply($document, $this->certificate());

        static::assertSame('KeyInfo', $keyInfo->localName);
        static::assertSame(self::DS, $keyInfo->namespaceURI);

        $str = $this->firstChildElement($keyInfo);
        static::assertSame('SecurityTokenReference', $str->localName);
        static::assertSame(self::WSSE, $str->namespaceURI);

        $reference = $this->firstChildElement($str);
        static::assertSame('Reference', $reference->localName);
        static::assertSame(self::WSSE, $reference->namespaceURI);
        static::assertSame('#token-1', $reference->getAttribute('URI'));
        static::assertSame('urn:value-type', $reference->getAttribute('ValueType'));
    }

    public function test_it_does_not_embed_a_binary_security_token_or_mutate_the_document(): void
    {
        $document = $this->document();
        $before = $document->toXmlString();

        $keyInfo = (new DirectReferenceKeyIdentifier('token-1', 'urn:value-type'))
            ->apply($document, $this->certificate());

        // The returned element is detached and no BST is created anywhere.
        static::assertNull($keyInfo->parentNode);
        static::assertSame($before, $document->toXmlString());
        static::assertSame(0, $keyInfo->getElementsByTagNameNS(self::WSSE, 'BinarySecurityToken')->length);
    }
}
