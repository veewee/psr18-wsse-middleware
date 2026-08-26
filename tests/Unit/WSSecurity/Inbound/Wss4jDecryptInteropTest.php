<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use VeeWee\Xml\Dom\Document;

/**
 * Decrypts a real Apache WSS4J message whose session key was wrapped with RSA-OAEP-SHA256 (xmlenc11 rsa-oaep
 * with a ds:DigestMethod sha256 and an xenc11:MGF mgf1sha256). It exercises the hand-rolled OAEP-SHA256 unwrap
 * against the reference implementation, not just an internal round trip.
 */
final class Wss4jDecryptInteropTest extends TestCase
{
    public function test_it_decrypts_a_real_wss4j_oaep_sha256_message(): void
    {
        $fixtures = __DIR__.'/../../../fixtures/interop';
        $document = Document::fromXmlString((string) file_get_contents($fixtures.'/wss4j-encrypted-oaep-sha256.xml'));
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());

        $recipientKey = Key::fromFile($fixtures.'/wss4j-recipient-php-client.key');

        (new Inbound\Decrypt($recipientKey))($context);

        $plaintext = $document->toXmlString();
        static::assertStringNotContainsString('EncryptedData', $plaintext);
        static::assertStringContainsString('<tns:Ping', $plaintext);
    }
}
