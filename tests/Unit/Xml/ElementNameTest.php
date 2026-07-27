<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Xml;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Xml\ElementName;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use VeeWee\Xml\Dom\Document;

final class ElementNameTest extends TestCase
{
    public function test_it_matches_a_local_name_in_a_namespace(): void
    {
        static::assertTrue(ElementName::matches($this->signature(), Namespaces::Ds, 'Signature'));
    }

    public function test_a_different_local_name_does_not_match(): void
    {
        static::assertFalse(ElementName::matches($this->signature(), Namespaces::Ds, 'SignedInfo'));
    }

    public function test_the_same_local_name_in_another_namespace_does_not_match(): void
    {
        // An unqualified or foreign-namespace element must never stand in for a namespaced one.
        static::assertFalse(ElementName::matches($this->signature(), Namespaces::Xenc, 'Signature'));
        static::assertFalse(ElementName::matches($this->unqualified(), Namespaces::Ds, 'Signature'));
    }

    public function test_it_matches_a_namespace_uri_outside_the_enum(): void
    {
        static::assertTrue(ElementName::matchesUri($this->signature(), Namespaces::Ds->value, 'Signature'));
        static::assertFalse(ElementName::matchesUri($this->signature(), 'urn:other', 'Signature'));
    }

    private function signature(): Element
    {
        return Document::fromXmlString('<ds:Signature xmlns:ds="'.Namespaces::Ds->value.'"/>')
            ->locateDocumentElement();
    }

    private function unqualified(): Element
    {
        return Document::fromXmlString('<Signature/>')->locateDocumentElement();
    }
}
