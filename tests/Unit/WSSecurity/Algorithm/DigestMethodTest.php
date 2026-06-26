<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Algorithm;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;

final class DigestMethodTest extends TestCase
{
    public function test_it_exposes_the_digest_algorithm_uris(): void
    {
        static::assertSame('http://www.w3.org/2000/09/xmldsig#sha1', DigestMethod::SHA1->value);
        static::assertSame('http://www.w3.org/2001/04/xmlenc#sha256', DigestMethod::SHA256->value);
        static::assertSame('http://www.w3.org/2001/04/xmldsig-more#sha384', DigestMethod::SHA384->value);
        static::assertSame('http://www.w3.org/2001/04/xmlenc#sha512', DigestMethod::SHA512->value);
        static::assertSame('http://www.w3.org/2001/04/xmlenc#ripemd160', DigestMethod::RIPEMD160->value);
    }

    public function test_the_secure_default_is_sha256(): void
    {
        static::assertSame(DigestMethod::SHA256, DigestMethod::default());
    }
}
