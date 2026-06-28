<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Algorithm;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;

final class SignatureCanonicalizationTest extends TestCase
{
    public function test_it_exposes_the_canonicalization_uris(): void
    {
        static::assertSame('http://www.w3.org/TR/2001/REC-xml-c14n-20010315', SignatureCanonicalization::C14N->value);
        static::assertSame('http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments', SignatureCanonicalization::C14N_COMMENTS->value);
        static::assertSame('http://www.w3.org/2001/10/xml-exc-c14n#', SignatureCanonicalization::EXC_C14N->value);
        static::assertSame('http://www.w3.org/2001/10/xml-exc-c14n#WithComments', SignatureCanonicalization::EXC_C14N_COMMENTS->value);
    }

    public function test_it_exposes_exactly_the_four_canonicalizations(): void
    {
        $cases = SignatureCanonicalization::cases();

        static::assertCount(4, $cases);
        static::assertContains(SignatureCanonicalization::C14N, $cases);
        static::assertContains(SignatureCanonicalization::C14N_COMMENTS, $cases);
        static::assertContains(SignatureCanonicalization::EXC_C14N, $cases);
        static::assertContains(SignatureCanonicalization::EXC_C14N_COMMENTS, $cases);
    }

    public function test_the_secure_default_is_exclusive_c14n(): void
    {
        static::assertSame(SignatureCanonicalization::EXC_C14N, SignatureCanonicalization::default());
    }

    public function test_it_reports_whether_a_method_is_exclusive(): void
    {
        static::assertTrue(SignatureCanonicalization::EXC_C14N->isExclusive());
        static::assertTrue(SignatureCanonicalization::EXC_C14N_COMMENTS->isExclusive());
        static::assertFalse(SignatureCanonicalization::C14N->isExclusive());
        static::assertFalse(SignatureCanonicalization::C14N_COMMENTS->isExclusive());
    }

    public function test_it_reports_whether_comments_are_retained(): void
    {
        static::assertTrue(SignatureCanonicalization::C14N_COMMENTS->withComments());
        static::assertTrue(SignatureCanonicalization::EXC_C14N_COMMENTS->withComments());
        static::assertFalse(SignatureCanonicalization::C14N->withComments());
        static::assertFalse(SignatureCanonicalization::EXC_C14N->withComments());
    }
}
