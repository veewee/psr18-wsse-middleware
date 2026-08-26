<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Algorithm;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;

final class DataEncryptionMethodTest extends TestCase
{
    public function test_it_exposes_the_data_encryption_uris(): void
    {
        static::assertSame('http://www.w3.org/2001/04/xmlenc#tripledes-cbc', DataEncryptionMethod::TRIPLEDES_CBC->value);
        static::assertSame('http://www.w3.org/2001/04/xmlenc#aes128-cbc', DataEncryptionMethod::AES128_CBC->value);
        static::assertSame('http://www.w3.org/2001/04/xmlenc#aes192-cbc', DataEncryptionMethod::AES192_CBC->value);
        static::assertSame('http://www.w3.org/2001/04/xmlenc#aes256-cbc', DataEncryptionMethod::AES256_CBC->value);
        static::assertSame('http://www.w3.org/2009/xmlenc11#aes128-gcm', DataEncryptionMethod::AES128_GCM->value);
        static::assertSame('http://www.w3.org/2009/xmlenc11#aes192-gcm', DataEncryptionMethod::AES192_GCM->value);
        static::assertSame('http://www.w3.org/2009/xmlenc11#aes256-gcm', DataEncryptionMethod::AES256_GCM->value);
    }

    public function test_the_secure_default_is_aes256_gcm(): void
    {
        static::assertSame(DataEncryptionMethod::AES256_GCM, DataEncryptionMethod::default());
    }

    public function test_it_exposes_the_iv_length_per_method(): void
    {
        // 96 bits for GCM; the block size for CBC (where the IV length equals the block size).
        static::assertSame(8, DataEncryptionMethod::TRIPLEDES_CBC->ivLength());
        static::assertSame(16, DataEncryptionMethod::AES128_CBC->ivLength());
        static::assertSame(16, DataEncryptionMethod::AES192_CBC->ivLength());
        static::assertSame(16, DataEncryptionMethod::AES256_CBC->ivLength());
        static::assertSame(12, DataEncryptionMethod::AES128_GCM->ivLength());
        static::assertSame(12, DataEncryptionMethod::AES192_GCM->ivLength());
        static::assertSame(12, DataEncryptionMethod::AES256_GCM->ivLength());
    }

    public function test_only_gcm_carries_an_authentication_tag(): void
    {
        static::assertSame(16, DataEncryptionMethod::AES256_GCM->tagLength());
        static::assertSame(0, DataEncryptionMethod::AES256_CBC->tagLength());
        static::assertSame(0, DataEncryptionMethod::TRIPLEDES_CBC->tagLength());
    }

    public function test_it_reports_whether_the_mode_is_gcm(): void
    {
        static::assertTrue(DataEncryptionMethod::AES128_GCM->isGcm());
        static::assertTrue(DataEncryptionMethod::AES256_GCM->isGcm());
        static::assertFalse(DataEncryptionMethod::AES256_CBC->isGcm());
        static::assertFalse(DataEncryptionMethod::TRIPLEDES_CBC->isGcm());
    }
}
