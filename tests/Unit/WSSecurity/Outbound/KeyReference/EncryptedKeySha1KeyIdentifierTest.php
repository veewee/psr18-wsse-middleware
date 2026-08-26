<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound\KeyReference;

use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncryptedKeySha1KeyIdentifier;

final class EncryptedKeySha1KeyIdentifierTest extends KeyIdentifierTestCase
{
    private const VALUE_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1';
    private const TOKEN_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey';

    public function test_the_identifier_is_the_digest_of_the_wrapped_bytes(): void
    {
        // The digest is over the bytes as they travel, so it is one both sides compute without either
        // revealing the secret. Pinned against the definition rather than against this package's own output.
        $wrapped = random_bytes(256);

        static::assertSame(
            base64_encode(sha1($wrapped, binary: true)),
            EncryptedKeySha1KeyIdentifier::forWrappedKey($wrapped)->value(),
        );
    }

    public function test_a_different_wrapped_key_is_named_differently(): void
    {
        static::assertNotSame(
            EncryptedKeySha1KeyIdentifier::forWrappedKey('one')->value(),
            EncryptedKeySha1KeyIdentifier::forWrappedKey('two')->value(),
        );
    }

    public function test_it_emits_the_wss_session_key_reference_with_its_token_type(): void
    {
        $document = $this->document();

        $keyInfo = (new EncryptedKeySha1KeyIdentifier('bmFtZQ=='))->apply($document);

        $str = $this->firstChildElement($keyInfo);
        static::assertSame('SecurityTokenReference', $str->localName);
        // A receiver enforcing the Basic Security Profile classifies a reference by this attribute and refuses
        // one it cannot classify.
        static::assertSame(self::TOKEN_TYPE, $str->getAttributeNS(self::WSSE11, 'TokenType'));

        $keyIdentifier = $this->firstChildElement($str);
        static::assertSame('KeyIdentifier', $keyIdentifier->localName);
        static::assertSame(self::VALUE_TYPE, $keyIdentifier->getAttribute('ValueType'));
        static::assertSame('bmFtZQ==', $keyIdentifier->textContent);
    }
}
