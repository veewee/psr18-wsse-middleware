<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Wsa;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Wsa\WsaNamespace;

final class WsaNamespaceTest extends TestCase
{
    public function test_it_exposes_the_addressing_namespace_uris(): void
    {
        static::assertSame('http://www.w3.org/2005/08/addressing', WsaNamespace::W3c200508->value);
        static::assertSame('http://schemas.xmlsoap.org/ws/2004/08/addressing', WsaNamespace::Submission200408->value);
    }

    public function test_the_prefix_is_wsa(): void
    {
        static::assertSame('wsa', WsaNamespace::W3c200508->prefix());
        static::assertSame('wsa', WsaNamespace::Submission200408->prefix());
    }

    public function test_each_version_has_its_own_anonymous_address(): void
    {
        static::assertSame(
            'http://www.w3.org/2005/08/addressing/anonymous',
            WsaNamespace::W3c200508->anonymousUri()
        );
        static::assertSame(
            'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous',
            WsaNamespace::Submission200408->anonymousUri()
        );
    }
}
