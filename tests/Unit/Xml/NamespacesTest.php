<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Xml;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespaces;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;

final class NamespacesTest extends TestCase
{
    public function test_it_exposes_the_standard_oasis_and_w3c_uris(): void
    {
        static::assertSame(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
            WsseNamespaces::Wsse->value
        );
        static::assertSame(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
            WsseNamespaces::Wsu->value
        );
        static::assertSame(
            'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd',
            WsseNamespaces::Wsse11->value
        );
        static::assertSame('http://www.w3.org/2000/09/xmldsig#', Namespaces::Ds->value);
        static::assertSame('http://www.w3.org/2001/04/xmlenc#', Namespaces::Xenc->value);
    }

    public function test_it_maps_each_namespace_to_its_canonical_prefix(): void
    {
        static::assertSame('wsse', WsseNamespaces::Wsse->prefix());
        static::assertSame('wsu', WsseNamespaces::Wsu->prefix());
        static::assertSame('wsse11', WsseNamespaces::Wsse11->prefix());
        static::assertSame('ds', Namespaces::Ds->prefix());
        static::assertSame('xenc', Namespaces::Xenc->prefix());
    }

    public function test_it_qualifies_a_local_name_with_the_prefix(): void
    {
        static::assertSame('wsse:Security', WsseNamespaces::Wsse->qualify('Security'));
        static::assertSame('wsu:Id', WsseNamespaces::Wsu->qualify('Id'));
        static::assertSame('ds:Signature', Namespaces::Ds->qualify('Signature'));
    }
}
