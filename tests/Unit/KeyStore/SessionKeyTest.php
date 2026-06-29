<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;

final class SessionKeyTest extends TestCase
{
    public function test_it_exposes_its_raw_bytes(): void
    {
        $key = SessionKey::fromBytes("\x00\x01\x02\x03");

        static::assertSame("\x00\x01\x02\x03", $key->bytes());
    }

    public function test_it_does_not_expose_its_bytes_in_a_dump(): void
    {
        $key = SessionKey::fromBytes('super-secret-session-key');

        static::assertStringNotContainsString('super-secret-session-key', print_r($key, true));
    }
}
