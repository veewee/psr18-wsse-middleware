<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Xml;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;

final class WsseNamespaceTest extends TestCase
{
    public function test_it_exposes_the_standard_oasis_and_w3c_uris(): void
    {
        static::assertSame(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
            WsseNamespace::Wsse->value
        );
        static::assertSame(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
            WsseNamespace::Wsu->value
        );
        static::assertSame(
            'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd',
            WsseNamespace::Wsse11->value
        );
        static::assertSame('http://www.w3.org/2000/09/xmldsig#', WsseNamespace::Ds->value);
        static::assertSame('http://www.w3.org/2001/04/xmlenc#', WsseNamespace::Xenc->value);
    }

    public function test_it_maps_each_namespace_to_its_canonical_prefix(): void
    {
        static::assertSame('wsse', WsseNamespace::Wsse->prefix());
        static::assertSame('wsu', WsseNamespace::Wsu->prefix());
        static::assertSame('wsse11', WsseNamespace::Wsse11->prefix());
        static::assertSame('ds', WsseNamespace::Ds->prefix());
        static::assertSame('xenc', WsseNamespace::Xenc->prefix());
    }

    public function test_it_qualifies_a_local_name_with_the_prefix(): void
    {
        static::assertSame('wsse:Security', WsseNamespace::Wsse->qualify('Security'));
        static::assertSame('wsu:Id', WsseNamespace::Wsu->qualify('Id'));
        static::assertSame('ds:Signature', WsseNamespace::Ds->qualify('Signature'));
    }
}
