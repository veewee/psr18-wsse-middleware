<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore\Metadata;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\KeyUsage;

final class KeyUsageTest extends TestCase
{
    public function test_it_permits_signing_when_digital_signature_is_present(): void
    {
        static::assertTrue(KeyUsage::fromExtension('Digital Signature, Key Encipherment')->permitsSigning());
    }

    public function test_it_forbids_signing_when_digital_signature_is_absent(): void
    {
        static::assertFalse(KeyUsage::fromExtension('Key Encipherment')->permitsSigning());
    }
}
