<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SigningFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\External\ExternalPartSignature;
use VeeWee\Xml\Dom\Document;

/**
 * A signature over an element whose content is an xop:Include covers the pointer, not the bytes. The signer
 * refuses that, unless the reference the pointer names is one of the external parts the same signature covers
 * in its own right.
 *
 * The verification side of the same rule is tested where the shape can be built at all: this signer will not
 * produce a message with an uncovered pointer, so ReferenceResolverTest constructs one by hand and the
 * java-interop suite has a WSS4J peer send a real one.
 *
 * The refusal is not a compatibility choice. A default WSS4J receiver does not expand such an element before
 * verifying, so a signature that covers only the pointer verifies there while the file it stands for travels
 * unprotected. Matching that would mean reproducing the weakness. The encryption side already refuses the
 * mirror image of it.
 */
#[RequiresPhp('>= 8.4.21')]
final class OptimizedContentCoverageTest extends TestCase
{
    private const XOP = 'http://www.w3.org/2004/08/xop/include';
    private const CID = 'cid:invoice@example.com';
    private const TRANSFORM = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform';

    public function test_it_refuses_to_sign_a_pointer_when_no_parts_were_registered(): void
    {
        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage('points at content the signature does not cover');

        WsseSignatureFixture::caSignedLeaf()->sign(
            [WsseSignatureFixture::bodyTarget()],
            body: $this->optimizedBody(self::CID),
        );
    }

    public function test_it_refuses_to_sign_a_pointer_naming_a_part_the_signature_does_not_cover(): void
    {
        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage('points at content the signature does not cover');

        WsseSignatureFixture::caSignedLeaf()->sign(
            [WsseSignatureFixture::bodyTarget()],
            body: $this->optimizedBody('cid:other@example.com'),
            externalParts: new ExternalPartSignature($this->parts(self::CID), self::TRANSFORM),
        );
    }

    public function test_it_refuses_to_sign_a_pointer_naming_nothing_at_all(): void
    {
        // An include without an href names no part, so it can never be one the signature covers.
        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage('points at content the signature does not cover');

        WsseSignatureFixture::caSignedLeaf()->sign(
            [WsseSignatureFixture::bodyTarget()],
            body: '<data><xop:Include xmlns:xop="'.self::XOP.'"/></data>',
            externalParts: new ExternalPartSignature($this->parts(self::CID), self::TRANSFORM),
        );
    }

    public function test_it_signs_a_pointer_whose_part_the_same_signature_covers(): void
    {
        // The supported MTOM shape: the element points at a part, and that part has a ds:Reference of its own.
        $document = $this->signOptimized();

        static::assertStringContainsString('URI="'.self::CID.'"', $document->toXmlString());
    }

    private function signOptimized(): Document
    {
        return WsseSignatureFixture::caSignedLeaf()->sign(
            [WsseSignatureFixture::bodyTarget()],
            body: $this->optimizedBody(self::CID),
            externalParts: new ExternalPartSignature($this->parts(self::CID), self::TRANSFORM),
        );
    }

    private function optimizedBody(string $reference): string
    {
        return '<data><xop:Include xmlns:xop="'.self::XOP.'" href="'.$reference.'"/></data>';
    }

    private function parts(string $reference): ExternalPartList
    {
        return ExternalPartList::of(new ExternalPart(
            $reference,
            'application/pdf',
            $this->stream('%PDF-1.7 invoice bytes'),
        ));
    }

    /**
     * @return ResourceStream<resource>
     */
    private function stream(string $contents): ResourceStream
    {
        return MemoryStream::create()->write($contents)->rewind();
    }
}
