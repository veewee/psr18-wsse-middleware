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

    public function test_it_permits_signing_when_only_non_repudiation_is_present(): void
    {
        // RFC 5280 asserts nonRepudiation (contentCommitment) for verifying signatures, so a certificate
        // carrying only that bit is a signing certificate. Qualified-signature PKIs issue them.
        static::assertTrue(KeyUsage::fromExtension('Non Repudiation')->permitsSigning());
    }

    public function test_it_forbids_signing_when_no_signing_bit_is_present(): void
    {
        static::assertFalse(KeyUsage::fromExtension('Key Encipherment')->permitsSigning());
    }
}
