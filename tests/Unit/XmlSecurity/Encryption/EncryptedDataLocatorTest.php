<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Encryption;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\WsuIdLookup;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedDataLocator;
use VeeWee\Xml\Dom\Document;

final class EncryptedDataLocatorTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';

    /** The WS-Security profile tags xenc:EncryptedData with wsu:Id, so the resolver uses that convention. */
    private function resolver(): EncryptedDataLocator
    {
        return new EncryptedDataLocator(new WsuIdLookup());
    }

    private function envelope(string $body): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsu="'.self::WSU.'" xmlns:xenc="'.self::XENC.'">'
            .'<soap:Header/><soap:Body>'.$body.'</soap:Body></soap:Envelope>'
        );
    }

    public function test_it_resolves_an_encrypted_data_carrying_a_wsu_id(): void
    {
        $document = $this->envelope('<xenc:EncryptedData wsu:Id="ED-1"/>');

        $element = $this->resolver()->resolve($document, 'ED-1');

        static::assertSame('EncryptedData', $element->localName);
        static::assertSame('ED-1', $element->getAttributeNS(self::WSU, 'Id'));
    }

    /** A common interop shape: a native @Id (no namespace), no wsu:Id. */
    public function test_it_resolves_an_encrypted_data_carrying_a_native_id(): void
    {
        $document = $this->envelope('<xenc:EncryptedData Id="ED-1"/>');

        $element = $this->resolver()->resolve($document, 'ED-1');

        static::assertSame('EncryptedData', $element->localName);
        static::assertSame('ED-1', $element->getAttribute('Id'));
    }

    public function test_it_throws_when_the_id_is_not_present(): void
    {
        $document = $this->envelope('<xenc:EncryptedData wsu:Id="ED-1"/>');

        $this->expectException(IdReferenceException::class);
        $this->resolver()->resolve($document, 'does-not-exist');
    }

    /**
     * An id shared across the native and profile conventions is still ambiguous: a native @Id on one
     * EncryptedDataLocator plus a duplicated wsu:Id on others must be rejected, never resolved to the native one.
     */
    public function test_it_rejects_an_id_shared_across_conventions(): void
    {
        $document = $this->envelope(
            '<xenc:EncryptedData Id="dup"/><xenc:EncryptedData wsu:Id="dup"/><xenc:EncryptedData wsu:Id="dup"/>'
        );

        $this->expectException(IdReferenceException::class);
        $this->resolver()->resolve($document, 'dup');
    }

    /** Two EncryptedDataLocator sharing an id is ambiguous and must be rejected, never "pick the first". */
    public function test_it_rejects_a_duplicate_id(): void
    {
        $document = $this->envelope(
            '<xenc:EncryptedData wsu:Id="dup"/><xenc:EncryptedData Id="dup"/>'
        );

        $this->expectException(IdReferenceException::class);
        $this->resolver()->resolve($document, 'dup');
    }

    /** A stray native @Id on a non-EncryptedDataLocator element must not be targeted. */
    public function test_it_ignores_a_matching_id_on_another_element_type(): void
    {
        $document = $this->envelope('<app:Op xmlns:app="urn:app" Id="ED-1"/>');

        $this->expectException(IdReferenceException::class);
        $this->resolver()->resolve($document, 'ED-1');
    }

    /** A crafted id must be treated as a literal value, never injected into the query. */
    public function test_it_is_not_vulnerable_to_xpath_injection(): void
    {
        $document = $this->envelope('<xenc:EncryptedData wsu:Id="ED-1"/>');

        $this->expectException(IdReferenceException::class);
        $this->resolver()->resolve($document, "x' or '1'='1");
    }
}
