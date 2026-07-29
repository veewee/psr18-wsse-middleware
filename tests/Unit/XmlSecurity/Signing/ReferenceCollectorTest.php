<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Signing;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\ReferenceCollector;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use VeeWee\Xml\Dom\Document;

final class ReferenceCollectorTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    public function test_it_mints_a_wsu_id_when_the_element_has_none(): void
    {
        $document = $this->document('<soap:Body><a/></soap:Body>');
        $references = $this->collector()->collect($document, [Target::element(self::SOAP, 'Body')]);

        $body = $references[0]->element;
        static::assertNotSame('', $references[0]->id);
        static::assertSame($references[0]->id, $body->getAttributeNS(self::WSU, 'Id'));
    }

    public function test_it_reuses_an_existing_wsu_id(): void
    {
        $document = $this->document('<soap:Body wsu:Id="Body-Existing"><a/></soap:Body>');
        $references = $this->collector()->collect($document, [Target::element(self::SOAP, 'Body')]);

        static::assertSame('Body-Existing', $references[0]->id);
    }

    public function test_it_preserves_first_seen_order(): void
    {
        $document = $this->document('<soap:Body wsu:Id="Body-1"><x:Extra xmlns:x="urn:x" wsu:Id="Extra-1"/></soap:Body>');
        $references = $this->collector()->collect($document, [
            Target::element('urn:x', 'Extra'),
            Target::element(self::SOAP, 'Body'),
        ]);

        static::assertSame(['Extra-1', 'Body-1'], [$references[0]->id, $references[1]->id]);
    }

    public function test_it_deduplicates_two_parts_resolving_to_the_same_element(): void
    {
        $document = $this->document('<soap:Body wsu:Id="Body-1"><a/></soap:Body>');
        $references = $this->collector()->collect($document, [Target::element(self::SOAP, 'Body'), Target::byId('Body-1')]);

        static::assertCount(1, $references);
    }

    public function test_it_propagates_a_missing_part(): void
    {
        $document = $this->document('<soap:Body/>');

        $this->expectException(IdReferenceException::class);
        $this->collector()->collect($document, [Target::byId('absent')]);
    }

    private function collector(): ReferenceCollector
    {
        // The minter and locator's lookup must share the wsu:Id convention, as the WS-Security profile pairs them.
        return new ReferenceCollector((new WsuIdConvention())->minter(), new TargetLocator((new WsuIdConvention())->lookup()));
    }

    private function document(string $bodyXml): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header/>'.$bodyXml
            .'</soap:Envelope>'
        );
    }
}
