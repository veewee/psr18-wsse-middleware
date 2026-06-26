<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\KeyHandle;

final class KeyHandleTest extends TestCase
{
    public function test_it_names_the_underlying_key_material(): void
    {
        $material = new Certificate('-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----');
        $handle = KeyHandle::for($material);

        static::assertSame($material, $handle->material());
    }
}
