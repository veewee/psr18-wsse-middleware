<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Random;

final class RandomTest extends TestCase
{
    public function test_it_generates_the_requested_number_of_bytes(): void
    {
        $random = new Random();

        foreach ([1, 8, 12, 16, 32] as $length) {
            static::assertSame($length, strlen($random->bytes($length)));
        }
    }

    public function test_it_does_not_repeat_its_output(): void
    {
        $random = new Random();

        static::assertNotSame($random->bytes(32), $random->bytes(32));
    }
}
