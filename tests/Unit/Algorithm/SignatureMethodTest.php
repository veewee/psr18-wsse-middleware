<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Algorithm;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;

final class SignatureMethodTest extends TestCase
{
    public function test_it_exposes_the_signature_algorithm_uris(): void
    {
        static::assertSame('http://www.w3.org/2000/09/xmldsig#rsa-sha1', SignatureMethod::RSA_SHA1->value);
        static::assertSame('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', SignatureMethod::RSA_SHA256->value);
        static::assertSame('http://www.w3.org/2001/04/xmldsig-more#rsa-sha384', SignatureMethod::RSA_SHA384->value);
        static::assertSame('http://www.w3.org/2001/04/xmldsig-more#rsa-sha512', SignatureMethod::RSA_SHA512->value);
        static::assertSame('http://www.w3.org/2000/09/xmldsig#dsa-sha1', SignatureMethod::DSA_SHA1->value);
        static::assertSame('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256', SignatureMethod::ECDSA_SHA256->value);
        static::assertSame('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384', SignatureMethod::ECDSA_SHA384->value);
        static::assertSame('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512', SignatureMethod::ECDSA_SHA512->value);
    }

    public function test_only_the_ecdsa_methods_report_as_ecdsa(): void
    {
        static::assertTrue(SignatureMethod::ECDSA_SHA256->isEcdsa());
        static::assertTrue(SignatureMethod::ECDSA_SHA384->isEcdsa());
        static::assertTrue(SignatureMethod::ECDSA_SHA512->isEcdsa());

        static::assertFalse(SignatureMethod::RSA_SHA256->isEcdsa());
        static::assertFalse(SignatureMethod::DSA_SHA1->isEcdsa());
    }

    public function test_the_secure_default_is_rsa_sha256(): void
    {
        static::assertSame(SignatureMethod::RSA_SHA256, SignatureMethod::default());
    }

    public function test_it_does_not_carry_the_miscategorised_rsa_oaep_key_transport_algorithm(): void
    {
        // RSA-OAEP is a key-transport algorithm and belongs to KeyEncryptionMethod, not a signature method.
        static::assertNull(SignatureMethod::tryFrom('http://www.w3.org/2009/xmlenc11#rsa-oaep'));
    }
}
