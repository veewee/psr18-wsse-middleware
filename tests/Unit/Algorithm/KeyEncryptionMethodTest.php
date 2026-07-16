<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Algorithm;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;

final class KeyEncryptionMethodTest extends TestCase
{
    public function test_it_exposes_the_key_transport_uris(): void
    {
        static::assertSame('http://www.w3.org/2001/04/xmlenc#rsa-1_5', KeyEncryptionMethod::RSA_1_5->value);
        static::assertSame('http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', KeyEncryptionMethod::RSA_OAEP_MGF1P->value);
        static::assertSame('http://www.w3.org/2009/xmlenc11#rsa-oaep', KeyEncryptionMethod::RSA_OAEP->value);
    }

    public function test_the_secure_default_is_rsa_oaep(): void
    {
        static::assertSame(KeyEncryptionMethod::RSA_OAEP, KeyEncryptionMethod::default());
    }
}
