<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Encryption;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\SessionKeyFactory;

final class SessionKeyFactoryTest extends TestCase
{
    /**
     * @return iterable<string, array{0: DataEncryptionMethod, 1: int}>
     */
    public static function methods(): iterable
    {
        yield 'aes-128-cbc' => [DataEncryptionMethod::AES128_CBC, 16];
        yield 'aes-192-cbc' => [DataEncryptionMethod::AES192_CBC, 24];
        yield 'aes-256-cbc' => [DataEncryptionMethod::AES256_CBC, 32];
        yield 'aes-128-gcm' => [DataEncryptionMethod::AES128_GCM, 16];
        yield 'aes-192-gcm' => [DataEncryptionMethod::AES192_GCM, 24];
        yield 'aes-256-gcm' => [DataEncryptionMethod::AES256_GCM, 32];
        yield 'tripledes-cbc' => [DataEncryptionMethod::TRIPLEDES_CBC, 24];
    }

    #[DataProvider('methods')]
    public function test_it_generates_a_key_of_the_length_the_method_takes(
        DataEncryptionMethod $method,
        int $length,
    ): void {
        $key = (new SessionKeyFactory())->generate($method->keyLength());

        static::assertSame($length, strlen($key->bytes()));
    }

    public function test_it_does_not_reuse_key_material(): void
    {
        $factory = new SessionKeyFactory();

        static::assertNotSame(
            $factory->generate(32)->bytes(),
            $factory->generate(32)->bytes(),
        );
    }
}
