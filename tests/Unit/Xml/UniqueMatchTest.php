<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Xml;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\UniqueMatch;
use VeeWee\Xml\Dom\Document;

final class UniqueMatchTest extends TestCase
{
    public function test_it_returns_the_single_match(): void
    {
        $element = $this->element();

        static::assertSame($element, UniqueMatch::require([$element], 'Body-1'));
    }

    public function test_no_match_is_reported_as_not_found(): void
    {
        $this->expectException(IdReferenceException::class);

        UniqueMatch::require([], 'Body-1');
    }

    public function test_several_matches_are_reported_as_ambiguous(): void
    {
        // A duplicate id is the XSW primitive: resolving it to either candidate would let an attacker choose.
        try {
            UniqueMatch::require([$this->element(), $this->element()], 'Body-1');
            static::fail('An ambiguous match must be refused.');
        } catch (IdReferenceException $exception) {
            static::assertTrue($exception->ambiguous);
        }
    }

    private function element(): Element
    {
        return Document::fromXmlString('<root/>')->locateDocumentElement();
    }
}
