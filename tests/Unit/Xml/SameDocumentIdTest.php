<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Xml;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Xml\SameDocumentId;

final class SameDocumentIdTest extends TestCase
{
    public function test_it_reads_the_fragment_of_a_same_document_reference(): void
    {
        static::assertSame('Body-1', SameDocumentId::parse('#Body-1'));
    }

    public function test_it_refuses_a_reference_that_leaves_the_document(): void
    {
        // An external URI would let a verifier digest bytes the message does not carry.
        static::assertNull(SameDocumentId::parse('http://example.com/doc#Body-1'));
        static::assertNull(SameDocumentId::parse('Body-1'));
    }

    public function test_it_refuses_an_empty_fragment(): void
    {
        static::assertNull(SameDocumentId::parse('#'));
        static::assertNull(SameDocumentId::parse(''));
    }
}
