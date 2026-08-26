<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Algorithm;

use LogicException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureKeyKind;
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
        static::assertSame('http://www.w3.org/2000/09/xmldsig#hmac-sha1', SignatureMethod::HMAC_SHA1->value);
        static::assertSame('http://www.w3.org/2001/04/xmldsig-more#hmac-sha224', SignatureMethod::HMAC_SHA224->value);
        static::assertSame('http://www.w3.org/2001/04/xmldsig-more#hmac-sha256', SignatureMethod::HMAC_SHA256->value);
        static::assertSame('http://www.w3.org/2001/04/xmldsig-more#hmac-sha384', SignatureMethod::HMAC_SHA384->value);
        static::assertSame('http://www.w3.org/2001/04/xmldsig-more#hmac-sha512', SignatureMethod::HMAC_SHA512->value);
    }

    public function test_every_method_reports_the_kind_of_key_it_needs(): void
    {
        static::assertSame(SignatureKeyKind::Rsa, SignatureMethod::RSA_SHA1->keyKind());
        static::assertSame(SignatureKeyKind::Rsa, SignatureMethod::RSA_SHA256->keyKind());
        static::assertSame(SignatureKeyKind::Rsa, SignatureMethod::RSA_SHA384->keyKind());
        static::assertSame(SignatureKeyKind::Rsa, SignatureMethod::RSA_SHA512->keyKind());
        static::assertSame(SignatureKeyKind::Dsa, SignatureMethod::DSA_SHA1->keyKind());
        static::assertSame(SignatureKeyKind::Ecdsa, SignatureMethod::ECDSA_SHA256->keyKind());
        static::assertSame(SignatureKeyKind::Ecdsa, SignatureMethod::ECDSA_SHA384->keyKind());
        static::assertSame(SignatureKeyKind::Ecdsa, SignatureMethod::ECDSA_SHA512->keyKind());
        static::assertSame(SignatureKeyKind::Hmac, SignatureMethod::HMAC_SHA1->keyKind());
        static::assertSame(SignatureKeyKind::Hmac, SignatureMethod::HMAC_SHA224->keyKind());
        static::assertSame(SignatureKeyKind::Hmac, SignatureMethod::HMAC_SHA256->keyKind());
        static::assertSame(SignatureKeyKind::Hmac, SignatureMethod::HMAC_SHA384->keyKind());
        static::assertSame(SignatureKeyKind::Hmac, SignatureMethod::HMAC_SHA512->keyKind());
    }

    public function test_an_hmac_method_states_the_key_length_it_prefers(): void
    {
        static::assertSame(20, SignatureMethod::HMAC_SHA1->hmacKeyLength());
        static::assertSame(28, SignatureMethod::HMAC_SHA224->hmacKeyLength());
        static::assertSame(32, SignatureMethod::HMAC_SHA256->hmacKeyLength());
        static::assertSame(48, SignatureMethod::HMAC_SHA384->hmacKeyLength());
        static::assertSame(64, SignatureMethod::HMAC_SHA512->hmacKeyLength());
    }

    public function test_asking_a_non_hmac_method_for_an_hmac_key_length_is_a_programming_error(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('RSA_SHA256');

        SignatureMethod::RSA_SHA256->hmacKeyLength();
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
