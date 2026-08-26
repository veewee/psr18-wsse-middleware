<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Xml;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use VeeWee\Xml\Dom\Document;

final class ChildElementsTest extends TestCase
{
    public function test_single_returns_the_only_matching_child(): void
    {
        $parent = $this->parent('<ds:SignedInfo/>');

        $child = ChildElements::single($parent, Namespaces::Ds, 'SignedInfo');

        static::assertNotNull($child);
        static::assertSame('SignedInfo', $child->localName);
    }

    public function test_single_returns_null_when_the_child_is_absent(): void
    {
        static::assertNull(ChildElements::single($this->parent(''), Namespaces::Ds, 'SignedInfo'));
    }

    public function test_single_returns_null_when_the_child_is_duplicated(): void
    {
        // An injected sibling must not be able to shadow the element a reader depends on.
        $parent = $this->parent('<ds:SignedInfo/><ds:SignedInfo/>');

        static::assertNull(ChildElements::single($parent, Namespaces::Ds, 'SignedInfo'));
    }

    public function test_single_ignores_a_matching_descendant_that_is_not_a_direct_child(): void
    {
        $parent = $this->parent('<ds:Object><ds:SignedInfo/></ds:Object>');

        static::assertNull(ChildElements::single($parent, Namespaces::Ds, 'SignedInfo'));
    }

    private function parent(string $children): \Dom\Element
    {
        return Document::fromXmlString(
            '<ds:Signature xmlns:ds="'.Namespaces::Ds->value.'">'.$children.'</ds:Signature>'
        )->locateDocumentElement();
    }
}
