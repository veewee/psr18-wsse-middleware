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

    public function test_the_secure_default_is_exclusive_c14n(): void
    {
        static::assertSame(SignatureCanonicalization::EXC_C14N, SignatureCanonicalization::default());
    }

    public function test_it_reports_whether_the_method_is_exclusive(): void
    {
        static::assertFalse(SignatureCanonicalization::C14N->isExclusive());
        static::assertFalse(SignatureCanonicalization::C14N_COMMENTS->isExclusive());
        static::assertTrue(SignatureCanonicalization::EXC_C14N->isExclusive());
        static::assertTrue(SignatureCanonicalization::EXC_C14N_COMMENTS->isExclusive());
    }

    public function test_it_reports_whether_comments_are_retained(): void
    {
        static::assertFalse(SignatureCanonicalization::C14N->withComments());
        static::assertTrue(SignatureCanonicalization::C14N_COMMENTS->withComments());
        static::assertFalse(SignatureCanonicalization::EXC_C14N->withComments());
        static::assertTrue(SignatureCanonicalization::EXC_C14N_COMMENTS->withComments());
    }
}
