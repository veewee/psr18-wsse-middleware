<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Result;

use Dom\Element;
use Dom\XMLDocument;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\WsuId;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedReferences;
use VeeWee\Xml\Dom\Document;

final class VerifiedReferencesTest extends TestCase
{
    private const WSU = Namespaces::Wsu;

    public function test_was_signed_is_true_only_for_an_exact_signed_instance(): void
    {
        $document = Document::fromXmlString($this->envelope());
        $timestamp = WsuId::resolve($document, 'TS-1');
        $body = WsuId::resolve($document, 'Body-1');

        $references = new VerifiedReferences([$timestamp]);

        static::assertTrue($references->wasSigned($timestamp));
        static::assertFalse($references->wasSigned($body));
    }

    /**
     * XSW-IDENTITY-1: a structurally identical element from a separate parse is NOT the verified instance, so
     * a post-verification DOM swap cannot pass an unsigned look-alike off as signed.
     */
    public function test_was_signed_is_false_for_an_equal_but_different_element(): void
    {
        $signed = WsuId::resolve(Document::fromXmlString($this->envelope()), 'TS-1');
        $lookAlike = WsuId::resolve(Document::fromXmlString($this->envelope()), 'TS-1');

        $references = new VerifiedReferences([$signed]);

        static::assertTrue($references->wasSigned($signed));
        static::assertFalse($references->wasSigned($lookAlike));
    }

    public function test_signed_ids_lists_the_wsu_ids_of_the_signed_elements(): void
    {
        $document = Document::fromXmlString($this->envelope());
        $timestamp = WsuId::resolve($document, 'TS-1');
        $body = WsuId::resolve($document, 'Body-1');

        $references = new VerifiedReferences([$timestamp, $body]);

        static::assertSame(['TS-1', 'Body-1'], $references->signedIds());
    }

    public function test_signed_ids_is_empty_when_no_references_are_held(): void
    {
        static::assertSame([], (new VerifiedReferences([]))->signedIds());
    }

    public function test_signed_ids_skips_a_signed_element_without_a_wsu_id(): void
    {
        $timestamp = WsuId::resolve(Document::fromXmlString($this->envelope()), 'TS-1');
        // The new Dom\ API returns null for the absent wsu:Id on this element, so it must not appear.
        $withoutId = XMLDocument::createFromString('<root/>')->documentElement;
        static::assertInstanceOf(Element::class, $withoutId);

        $references = new VerifiedReferences([$withoutId, $timestamp]);

        static::assertSame(['TS-1'], $references->signedIds());
    }

    /**
     * @return non-empty-string
     */
    private function envelope(): string
    {
        return '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsu="'.self::WSU->value.'">'
            .'<soap:Header><wsu:Timestamp wsu:Id="TS-1"/></soap:Header>'
            .'<soap:Body wsu:Id="Body-1"/></soap:Envelope>';
    }
}
