<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore\Metadata;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\Thumbprint;

final class ThumbprintTest extends TestCase
{
    public function test_it_renders_raw_bytes_as_base64(): void
    {
        $bytes = sha1('certificate', true);

        static::assertSame(base64_encode($bytes), Thumbprint::fromRawBytes($bytes)->toBase64());
    }

    public function test_it_throws_on_empty_bytes(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        Thumbprint::fromRawBytes('');
    }

    public function test_it_round_trips_through_base64(): void
    {
        $base64 = base64_encode(sha1('certificate', true));

        static::assertSame($base64, Thumbprint::fromBase64($base64)->toBase64());
    }

    public function test_it_throws_on_invalid_base64(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        Thumbprint::fromBase64('!!!not base64!!!');
    }

    public function test_it_equals_the_same_thumbprint_built_either_way(): void
    {
        $bytes = sha1('certificate', true);

        static::assertTrue(Thumbprint::fromRawBytes($bytes)->equals(Thumbprint::fromBase64(base64_encode($bytes))));
    }

    public function test_it_does_not_equal_a_different_thumbprint(): void
    {
        static::assertFalse(
            Thumbprint::fromRawBytes(sha1('a', true))->equals(Thumbprint::fromRawBytes(sha1('b', true))),
        );
    }
}
