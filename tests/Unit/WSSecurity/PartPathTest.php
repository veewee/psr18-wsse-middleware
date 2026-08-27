<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity;

use Dom\Element;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\PartKind;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\Xml\QualifiedName;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetKind;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;

/**
 * The Body is required to be the Body of the envelope, not merely the one element in the document carrying
 * that name. Requiring it by name alone was satisfied by the genuinely signed Body parked anywhere, so a
 * receiver could accept a message whose Body slot had been emptied.
 */
final class PartPathTest extends TestCase
{
    public function test_the_body_part_lowers_to_the_path_of_the_envelope_body(): void
    {
        $target = Part::body()->toTarget(SoapVersion::Soap12);

        static::assertSame(TargetKind::Path, $target->kind());
        static::assertSame(
            ['Envelope', 'Body'],
            array_map(static fn (QualifiedName $step): string => $step->localName, $target->steps()),
        );
    }

    public function test_a_caller_can_name_the_path_of_an_element_of_their_own(): void
    {
        $part = Part::path(
            new QualifiedName(WsseSignatureFixture::SOAP, 'Envelope'),
            new QualifiedName(WsseSignatureFixture::SOAP, 'Body'),
            new QualifiedName('urn:app', 'Order'),
        );

        static::assertSame(PartKind::Path, $part->kind());
        static::assertFalse($part->kind()->isDynamic());
        static::assertCount(3, $part->toTarget(SoapVersion::Soap12)->steps());
    }

    public function test_two_paths_naming_the_same_steps_are_equal(): void
    {
        $one = Part::path(new QualifiedName('urn:a', 'A'), new QualifiedName('urn:b', 'B'));
        $same = Part::path(new QualifiedName('urn:a', 'A'), new QualifiedName('urn:b', 'B'));
        $other = Part::path(new QualifiedName('urn:a', 'A'), new QualifiedName('urn:b', 'C'));

        static::assertTrue($one->equals($same));
        static::assertFalse($one->equals($other));
    }

    /**
     * The finding this closes. The genuinely signed Body is moved into ds:Object inside the Security header
     * and the Body slot is left empty. Exactly one soap:Body remains, it is the instance the signature covered,
     * and identity matches, so requiring it by name alone accepted a message with no Body where a Body belongs.
     */
    #[RequiresPhp('>= 8.4.21')]
    public function test_a_signed_body_relocated_out_of_the_envelope_no_longer_satisfies_the_requirement(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $dom = $document->toUnsafeDocument();
        $body = $dom->getElementsByTagNameNS(WsseSignatureFixture::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);
        $security = $dom->getElementsByTagNameNS(WsseSignatureFixture::WSSE, 'Security')->item(0);
        static::assertInstanceOf(Element::class, $security);

        $object = $dom->createElementNS(WsseSignatureFixture::DS, 'ds:Object');
        $object->appendChild($body);
        $security->appendChild($object);

        $this->expectException(SecurityFault::class);
        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate), signed: [Part::body()]))(
            new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys()),
        );
    }

    /**
     * The control: an untouched message still verifies, so the refusal above is the relocation and not the
     * path itself.
     */
    #[RequiresPhp('>= 8.4.21')]
    public function test_an_untouched_signed_body_still_satisfies_the_requirement(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate), signed: [Part::body()]))(
            new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys()),
        );

        static::assertStringContainsString('<soap:Body', $document->toXmlString());
    }
}
