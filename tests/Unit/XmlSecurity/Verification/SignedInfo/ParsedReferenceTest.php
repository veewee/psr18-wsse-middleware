<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification\SignedInfo;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ParsedReference;

final class ParsedReferenceTest extends TestCase
{
    private const SWA_CONTENT = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform';

    private const STR_TRANSFORM = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform';

    public function test_it_refuses_a_reference_that_names_neither_a_canonicalization_nor_an_external_transform(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'A reference is digested either under a canonicalization or under an external transform.',
        );

        new ParsedReference(DigestMethod::SHA256, base64_encode('x'), null, []);
    }

    public function test_it_refuses_a_reference_that_names_both(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'A reference is digested either under a canonicalization or under an external transform.',
        );

        new ParsedReference(
            DigestMethod::SHA256,
            base64_encode('x'),
            SignatureCanonicalization::EXC_C14N,
            [],
            self::SWA_CONTENT,
        );
    }

    public function test_it_refuses_an_external_reference_that_also_declares_an_indirection(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'An external reference names octets, so there is no element for an indirection to resolve to.',
        );

        new ParsedReference(
            DigestMethod::SHA256,
            base64_encode('x'),
            null,
            [],
            self::SWA_CONTENT,
            self::STR_TRANSFORM,
        );
    }

    public function test_it_accepts_an_indirection_alongside_a_canonicalization(): void
    {
        $reference = new ParsedReference(
            DigestMethod::SHA256,
            base64_encode('x'),
            SignatureCanonicalization::EXC_C14N,
            [],
            dereferencingTransform: self::STR_TRANSFORM,
        );

        static::assertFalse($reference->isExternal());
        static::assertSame(self::STR_TRANSFORM, $reference->dereferencingTransform);
    }
}
