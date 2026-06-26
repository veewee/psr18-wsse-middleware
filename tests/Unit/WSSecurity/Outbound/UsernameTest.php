<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Dom\Element;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Username;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use VeeWee\Xml\Dom\Document;

final class UsernameTest extends TestCase
{
    private const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const TEXT_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText';
    private const DIGEST_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest';
    private const BASE64_BINARY = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    private function envelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Header/><soap:Body/></soap:Envelope>'
        );
    }

    private function context(Document $document): WsseContext
    {
        return new WsseContext($document, SoapVersion::Soap12);
    }

    /** @return list<Element> */
    private function elements(Document $document, string $namespace, string $localName): array
    {
        $found = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS($namespace, $localName) as $element) {
            $found[] = $element;
        }

        return $found;
    }

    private function maybeOnly(Document $document, string $namespace, string $localName): ?Element
    {
        return $this->elements($document, $namespace, $localName)[0] ?? null;
    }

    public function test_it_adds_a_username_token_in_text_mode(): void
    {
        $document = $this->envelope();

        (new Username('alice', 'secret'))($this->context($document));

        static::assertSame('alice', $this->maybeOnly($document, self::WSSE, 'Username')?->textContent);
        $password = $this->maybeOnly($document, self::WSSE, 'Password');
        static::assertNotNull($password);
        static::assertSame(self::TEXT_TYPE, $password->getAttribute('Type'));
        static::assertSame('secret', $password->textContent);
    }

    public function test_text_mode_omits_nonce_and_created(): void
    {
        $document = $this->envelope();

        (new Username('alice', 'secret'))($this->context($document));

        static::assertCount(0, $this->elements($document, self::WSSE, 'Nonce'));
        static::assertCount(0, $this->elements($document, self::WSU, 'Created'));
    }

    public function test_no_password_produces_no_password_element(): void
    {
        $document = $this->envelope();

        (new Username('alice'))($this->context($document));

        static::assertSame('alice', $this->maybeOnly($document, self::WSSE, 'Username')?->textContent);
        static::assertCount(0, $this->elements($document, self::WSSE, 'Password'));
    }

    public function test_digest_mode_emits_a_digest_password_with_nonce_and_created(): void
    {
        $document = $this->envelope();

        (new Username('alice', 'secret'))->withDigest(true)($this->context($document));

        $password = $this->maybeOnly($document, self::WSSE, 'Password');
        static::assertNotNull($password);
        static::assertSame(self::DIGEST_TYPE, $password->getAttribute('Type'));
        static::assertCount(1, $this->elements($document, self::WSSE, 'Nonce'));
        static::assertCount(1, $this->elements($document, self::WSU, 'Created'));
    }

    public function test_nonce_is_base64_of_sixteen_raw_bytes(): void
    {
        $document = $this->envelope();

        (new Username('alice', 'secret'))->withDigest(true)($this->context($document));

        $nonce = $this->maybeOnly($document, self::WSSE, 'Nonce');
        static::assertNotNull($nonce);
        static::assertSame(self::BASE64_BINARY, $nonce->getAttribute('EncodingType'));
        $raw = base64_decode($nonce->textContent, true);
        static::assertNotFalse($raw);
        static::assertSame(16, strlen($raw));
    }

    public function test_digest_value_recomputes_from_the_emitted_nonce_and_created(): void
    {
        $document = $this->envelope();

        (new Username('alice', 'secret'))->withDigest(true)($this->context($document));

        $nonce = base64_decode($this->maybeOnly($document, self::WSSE, 'Nonce')?->textContent ?? '', true);
        static::assertNotFalse($nonce);
        $created = $this->maybeOnly($document, self::WSU, 'Created')?->textContent ?? '';
        $expected = base64_encode((new Digest())->hash($nonce.$created.'secret', DigestMethod::SHA1));

        static::assertSame($expected, $this->maybeOnly($document, self::WSSE, 'Password')?->textContent);
    }

    public function test_each_call_produces_a_fresh_nonce(): void
    {
        $first = $this->envelope();
        $second = $this->envelope();

        $block = (new Username('alice', 'secret'))->withDigest(true);
        $block($this->context($first));
        $block($this->context($second));

        static::assertNotSame(
            $this->maybeOnly($first, self::WSSE, 'Nonce')?->textContent,
            $this->maybeOnly($second, self::WSSE, 'Nonce')?->textContent,
        );
    }

    public function test_digest_without_a_password_throws_on_invoke(): void
    {
        $document = $this->envelope();

        $this->expectException(InvalidArgumentException::class);

        (new Username('alice'))->withDigest(true)($this->context($document));
    }

    public function test_with_password_and_with_digest_are_immutable(): void
    {
        $original = new Username('alice');

        static::assertNotSame($original, $original->withPassword('secret'));
        static::assertNotSame($original, $original->withDigest(true));
    }
}
