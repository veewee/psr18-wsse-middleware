<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\BinarySecurityToken;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Timestamp;

final class BinarySecurityTokenTest extends OutboundTestCase
{
    private const X509V3 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
    private const BASE64_BINARY = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    private function certificate(): Certificate
    {
        return Certificate::fromFile(FIXTURE_DIR.'/certificates/wsse-client-x509.pem');
    }

    public function test_it_adds_a_binary_security_token_to_the_security_header(): void
    {
        $document = $this->envelope();

        (new BinarySecurityToken($this->certificate()))($this->context($document));

        $security = $this->only($document, self::WSSE, 'Security');
        $bst = $this->only($document, self::WSSE, 'BinarySecurityToken');
        static::assertSame($security, $bst->parentNode);
    }

    public function test_value_type_is_x509v3(): void
    {
        $document = $this->envelope();

        (new BinarySecurityToken($this->certificate()))($this->context($document));

        static::assertSame(self::X509V3, $this->only($document, self::WSSE, 'BinarySecurityToken')->getAttribute('ValueType'));
    }

    public function test_encoding_type_is_base64_binary(): void
    {
        $document = $this->envelope();

        (new BinarySecurityToken($this->certificate()))($this->context($document));

        static::assertSame(self::BASE64_BINARY, $this->only($document, self::WSSE, 'BinarySecurityToken')->getAttribute('EncodingType'));
    }

    public function test_body_is_the_base64_der_of_the_certificate(): void
    {
        $document = $this->envelope();

        (new BinarySecurityToken($this->certificate()))($this->context($document));

        $body = $this->only($document, self::WSSE, 'BinarySecurityToken')->textContent;
        $der = base64_decode($body, true);
        static::assertNotFalse($der);

        $expectedPem = preg_replace('/-----[^-]+-----|\s/', '', $this->certificate()->contents());
        static::assertSame($expectedPem, base64_encode($der));
    }

    public function test_the_token_carries_a_minted_wsu_id(): void
    {
        $document = $this->envelope();

        (new BinarySecurityToken($this->certificate()))($this->context($document));

        $id = $this->only($document, self::WSSE, 'BinarySecurityToken')->getAttributeNS(self::WSU, 'Id');
        static::assertMatchesRegularExpression('/^id-[0-9a-f-]{36}$/', $id);
    }

    public function test_the_token_precedes_a_timestamp_in_canonical_order(): void
    {
        $document = $this->envelope();
        $context = $this->context($document);

        (new Timestamp())($context);
        (new BinarySecurityToken($this->certificate()))($context);

        $security = $this->only($document, self::WSSE, 'Security');
        $order = [];
        foreach ($security->childNodes as $child) {
            if ($child instanceof Element) {
                $order[] = $child->localName;
            }
        }

        static::assertSame(['BinarySecurityToken', 'Timestamp'], $order);
    }
}
