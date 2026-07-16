<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Validator;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\Validator\RequiredPartsValidator;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\XmlSecurity\PartLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedReferences;
use VeeWee\Xml\Dom\Document;

/**
 * The validator asserts each required part is in the verified signed set by object identity, locating the
 * live element through the same hardened locator the verifier used. These tests run the real locator against
 * small documents and control the signed set with elements they locate themselves.
 */
final class RequiredPartsValidatorTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';

    public function test_it_passes_when_every_required_part_is_in_the_signed_set(): void
    {
        $document = $this->envelope();
        $body = $this->body($document);

        $this->validator()->validate($document, new VerifiedReferences([$body]), [Part::body()]);
        $this->addToAssertionCount(1);
    }

    public function test_it_throws_when_a_required_part_is_not_in_the_signed_set(): void
    {
        $document = $this->envelope();

        $this->expectException(SecurityFault::class);
        $this->validator()->validate($document, new VerifiedReferences([]), [Part::body()]);
    }

    public function test_it_rejects_a_structurally_identical_but_different_instance(): void
    {
        $xml = $this->xml();
        $document = Document::fromXmlString($xml);
        $otherDocument = Document::fromXmlString($xml);

        $liveBody = $this->body($document);
        $foreignBody = $this->body($otherDocument);
        static::assertNotSame($liveBody, $foreignBody);

        $this->expectException(SecurityFault::class);
        $this->validator()->validate($document, new VerifiedReferences([$foreignBody]), [Part::body()]);
    }

    public function test_it_maps_a_missing_required_element_to_a_security_fault(): void
    {
        $document = $this->envelope();

        try {
            $this->validator()->validate($document, new VerifiedReferences([]), [Part::timestamp()]);
            static::fail('Expected a SecurityFault.');
        } catch (SecurityFault $fault) {
            static::assertInstanceOf(IdReferenceException::class, $fault->getPrevious());
        }
    }

    public function test_an_empty_required_list_passes(): void
    {
        $document = $this->envelope();

        $this->expectNotToPerformAssertions();
        $this->validator()->validate($document, new VerifiedReferences([]), []);
    }

    private function validator(): RequiredPartsValidator
    {
        return new RequiredPartsValidator(new PartLocator());
    }

    private function envelope(): Document
    {
        return Document::fromXmlString($this->xml());
    }

    private function xml(): string
    {
        return '<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Body><data>x</data></soap:Body></soap:Envelope>';
    }

    private function body(Document $document): Element
    {
        $body = $document->toUnsafeDocument()->getElementsByTagNameNS(self::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);

        return $body;
    }
}
