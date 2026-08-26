<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Validator;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Validator\RequiredPartsValidator;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
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
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

    public function test_it_passes_when_every_required_part_is_in_the_signed_set(): void
    {
        $document = $this->envelope();
        $body = $this->body($document);

        $this->validator()->validate($document, SoapVersion::Soap12, new VerifiedReferences([$body]), [Part::body()]);
        $this->addToAssertionCount(1);
    }

    public function test_it_throws_when_a_required_part_is_not_in_the_signed_set(): void
    {
        $document = $this->envelope();

        $this->expectException(SecurityFault::class);
        $this->validator()->validate($document, SoapVersion::Soap12, new VerifiedReferences([]), [Part::body()]);
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
        $this->validator()->validate($document, SoapVersion::Soap12, new VerifiedReferences([$foreignBody]), [Part::body()]);
    }

    public function test_it_maps_a_missing_required_element_to_a_security_fault(): void
    {
        $document = $this->envelope();

        try {
            $this->validator()->validate($document, SoapVersion::Soap12, new VerifiedReferences([]), [Part::timestamp()]);
            static::fail('Expected a SecurityFault.');
        } catch (SecurityFault $fault) {
            static::assertInstanceOf(IdReferenceException::class, $fault->getPrevious());
        }
    }

    public function test_an_empty_required_list_passes(): void
    {
        $document = $this->envelope();

        $this->validator()->validate($document, SoapVersion::Soap12, new VerifiedReferences([]), []);

        // The same document and signed set fail a non-empty requirement, so the pass above came from
        // consulting the required list, not from skipping the validation.
        $this->expectException(SecurityFault::class);
        $this->validator()->validate($document, SoapVersion::Soap12, new VerifiedReferences([]), [Part::body()]);
    }

    public function test_security_header_contents_passes_when_every_child_except_the_signature_was_signed(): void
    {
        $document = $this->envelopeWithSecurity(
            '<wsu:Timestamp xmlns:wsu="'.self::WSU.'"/><ds:Signature xmlns:ds="'.self::DS.'"/>'
        );
        $timestamp = $this->locate($document, self::WSU, 'Timestamp');

        // The ds:Signature is intentionally NOT in the signed set. A signature never covers itself.
        $this->validator()->validate(
            $document,
            SoapVersion::Soap12,
            new VerifiedReferences([$timestamp]),
            [Part::securityHeaderContents()],
        );
        $this->addToAssertionCount(1);
    }

    public function test_security_header_contents_throws_when_a_non_signature_child_was_not_signed(): void
    {
        $document = $this->envelopeWithSecurity(
            '<wsu:Timestamp xmlns:wsu="'.self::WSU.'"/><ds:Signature xmlns:ds="'.self::DS.'"/>'
        );

        $this->expectException(SecurityFault::class);
        $this->validator()->validate(
            $document,
            SoapVersion::Soap12,
            new VerifiedReferences([]),
            [Part::securityHeaderContents()],
        );
    }

    public function test_soap_headers_passes_when_every_header_except_the_security_header_was_signed(): void
    {
        $document = $this->envelopeWithSecurity(
            '<ds:Signature xmlns:ds="'.self::DS.'"/>',
            '<wsa:To xmlns:wsa="urn:wsa">urn:svc</wsa:To>'
        );
        $to = $this->locate($document, 'urn:wsa', 'To');

        $this->validator()->validate(
            $document,
            SoapVersion::Soap12,
            new VerifiedReferences([$to]),
            [Part::soapHeaders()],
        );
        $this->addToAssertionCount(1);
    }

    public function test_soap_headers_throws_when_a_non_security_header_was_not_signed(): void
    {
        $document = $this->envelopeWithSecurity('', '<wsa:To xmlns:wsa="urn:wsa">urn:svc</wsa:To>');

        $this->expectException(SecurityFault::class);
        $this->validator()->validate(
            $document,
            SoapVersion::Soap12,
            new VerifiedReferences([]),
            [Part::soapHeaders()],
        );
    }

    public function test_a_dynamic_part_is_vacuously_satisfied_when_it_expands_to_nothing(): void
    {
        // Only the signature is present, so securityHeaderContents (which excludes it) has no member to require.
        $document = $this->envelopeWithSecurity('<ds:Signature xmlns:ds="'.self::DS.'"/>');

        $this->validator()->validate(
            $document,
            SoapVersion::Soap12,
            new VerifiedReferences([]),
            [Part::securityHeaderContents()],
        );

        // As soon as the header gains a non-signature child the same requirement bites, so the pass above
        // came from a real expansion that found no member, not from ignoring the dynamic part.
        $withToken = $this->envelopeWithSecurity(
            '<ds:Signature xmlns:ds="'.self::DS.'"/><wsse:UsernameToken/>'
        );

        $this->expectException(SecurityFault::class);
        $this->validator()->validate(
            $withToken,
            SoapVersion::Soap12,
            new VerifiedReferences([]),
            [Part::securityHeaderContents()],
        );
    }

    public function test_a_dynamic_part_is_refused_when_there_is_no_security_header(): void
    {
        // Demanding that the Security header's contents be signed cannot be satisfied by a message that
        // carries no such header: an empty member list would make the requirement vacuously true.
        $document = $this->envelope();

        $this->expectException(SecurityFault::class);
        $this->validator()->validate(
            $document,
            SoapVersion::Soap12,
            new VerifiedReferences([]),
            [Part::securityHeaderContents()],
        );
    }

    public function test_a_role_attribute_planted_on_the_security_header_cannot_void_the_requirement(): void
    {
        // The wsse:Security element is not itself a signed reference target, so an attacker in the middle can
        // stamp an actor/role on the genuine header without disturbing the signature. That makes the header
        // read as another hop's, and an unsigned token would ride along inside it unchecked.
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'"><soap:Header>'
            .'<wsse:Security soap:role="urn:attacker"><wsse:UsernameToken/></wsse:Security>'
            .'</soap:Header><soap:Body><data>x</data></soap:Body></soap:Envelope>'
        );

        $this->expectException(SecurityFault::class);
        $this->validator()->validate(
            $document,
            SoapVersion::Soap12,
            new VerifiedReferences([]),
            [Part::securityHeaderContents()],
        );
    }

    public function test_soap_headers_is_refused_when_the_security_header_was_relocated_out_of_the_soap_header(): void
    {
        // A hostile response could relocate wsse:Security to the document root. The header is then not the one
        // addressed to us, so the requirement is refused through the uniform fault rather than passing empty.
        $document = Document::fromXmlString(
            '<wsse:Security xmlns:wsse="'.self::WSSE.'"><ds:Signature xmlns:ds="'.self::DS.'"/></wsse:Security>'
        );

        $this->expectException(SecurityFault::class);
        $this->validator()->validate($document, SoapVersion::Soap12, new VerifiedReferences([]), [Part::soapHeaders()]);
    }

    private function validator(): RequiredPartsValidator
    {
        return new RequiredPartsValidator(new TargetLocator());
    }

    private function envelope(): Document
    {
        return Document::fromXmlString($this->xml());
    }

    private function xml(): string
    {
        return '<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Body><data>x</data></soap:Body></soap:Envelope>';
    }

    private function envelopeWithSecurity(string $securityChildren, string $otherHeaders = ''): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'">'
            .'<soap:Header>'.$otherHeaders.'<wsse:Security>'.$securityChildren.'</wsse:Security></soap:Header>'
            .'<soap:Body><data>x</data></soap:Body>'
            .'</soap:Envelope>'
        );
    }

    private function body(Document $document): Element
    {
        return $this->locate($document, self::SOAP, 'Body');
    }

    private function locate(Document $document, string $namespace, string $localName): Element
    {
        $element = $document->toUnsafeDocument()->getElementsByTagNameNS($namespace, $localName)->item(0);
        static::assertInstanceOf(Element::class, $element);

        return $element;
    }
}
