<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Xml\Locator;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\Locator\WsuId;
use VeeWee\Xml\Dom\Document;

final class WsuIdTest extends TestCase
{
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    private function envelope(string $body): string
    {
        return <<<XML
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsu="{$this->wsu()}">
          <soap:Header/>
          <soap:Body wsu:Id="Body-1">{$body}</soap:Body>
        </soap:Envelope>
        XML;
    }

    private function wsu(): string
    {
        return self::WSU;
    }

    public function test_it_resolves_a_unique_wsu_id_to_the_exact_element(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header><wsu:Timestamp wsu:Id="TS-1"/></soap:Header>'
            .'<soap:Body wsu:Id="Body-1"/></soap:Envelope>'
        );

        $element = WsuId::resolve($document, 'TS-1');

        static::assertSame('Timestamp', $element->localName);
        static::assertSame('TS-1', $element->getAttributeNS(self::WSU, 'Id'));
    }

    public function test_it_throws_when_the_id_is_not_present(): void
    {
        $document = Document::fromXmlString($this->envelope(''));

        $this->expectException(IdReferenceException::class);
        WsuId::resolve($document, 'does-not-exist');
    }

    /** XSW-1: two elements sharing a wsu:Id is ambiguous and must be rejected, never "pick the first". */
    public function test_xsw_1_it_rejects_duplicate_wsu_ids(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header><wsu:Timestamp wsu:Id="dup"/></soap:Header>'
            .'<soap:Body wsu:Id="dup"/></soap:Envelope>'
        );

        $this->expectException(IdReferenceException::class);
        WsuId::resolve($document, 'dup');
    }

    /** XPATH-1: a crafted id must be treated as a literal value, never injected into the query. */
    public function test_xpath_1_it_is_not_vulnerable_to_xpath_injection(): void
    {
        $document = Document::fromXmlString($this->envelope(''));

        // Classic injection: would match every element if interpolated unescaped.
        $this->expectException(IdReferenceException::class);
        WsuId::resolve($document, "x' or '1'='1");
    }

    public function test_it_handles_an_id_containing_a_single_quote_as_a_literal(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header><wsu:Timestamp wsu:Id="it&apos;s-me"/></soap:Header>'
            .'<soap:Body/></soap:Envelope>'
        );

        $element = WsuId::resolve($document, "it's-me");

        static::assertSame('Timestamp', $element->localName);
    }

    /** Exercises the concat() branch of the literal builder: a value containing BOTH quote characters. */
    public function test_it_handles_an_id_containing_both_quote_types_as_a_literal(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header><wsu:Timestamp wsu:Id="a&apos;&quot;b"/></soap:Header>'
            .'<soap:Body/></soap:Envelope>'
        );

        $element = WsuId::resolve($document, 'a\'"b');

        static::assertSame('Timestamp', $element->localName);
    }
}
