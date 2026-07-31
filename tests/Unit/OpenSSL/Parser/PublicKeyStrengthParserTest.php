<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Parser;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\PublicKeyFamily;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\PublicKeyStrengthParser;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;

final class PublicKeyStrengthParserTest extends TestCase
{
    public function test_it_reads_an_rsa_key_family_and_size(): void
    {
        $strength = (new PublicKeyStrengthParser())->parse(
            WsseSignatureFixture::caSignedLeafWithRsaBits(1024)->leafCertificate,
        );

        static::assertNotNull($strength);
        static::assertSame(PublicKeyFamily::Rsa, $strength->family);
        static::assertSame(1024, $strength->bits);
    }

    /**
     * The family is read, not assumed from the size: 256 bits is a strong elliptic-curve key and a broken RSA
     * one, so a floor can only be applied once the family is known.
     */
    public function test_it_reads_an_elliptic_curve_key_family_and_size(): void
    {
        $strength = (new PublicKeyStrengthParser())->parse(
            WsseSignatureFixture::ecCaSignedLeaf()->leafCertificate,
        );

        static::assertNotNull($strength);
        static::assertSame(PublicKeyFamily::Ec, $strength->family);
        static::assertSame(256, $strength->bits);
    }

    /**
     * A certificate whose key cannot be read yields null rather than throwing: nothing downstream can verify a
     * signature with it either, so the signature check refuses it with a reason of its own.
     */
    public function test_a_certificate_whose_key_cannot_be_read_yields_no_strength(): void
    {
        static::assertNull((new PublicKeyStrengthParser())->parse(new Certificate('not a certificate')));
    }
}
