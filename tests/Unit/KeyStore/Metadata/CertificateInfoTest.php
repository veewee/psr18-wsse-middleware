<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore\Metadata;

use PHPUnit\Framework\TestCase;
use Psl\DateTime\Timestamp;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\CertificateInfo;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\IssuerSerial;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\KeyUsage;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\SerialNumber;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\Thumbprint;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\ValidityWindow;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;

final class CertificateInfoTest extends TestCase
{
    public function test_it_exposes_the_subject_and_validity_window(): void
    {
        $info = $this->info();

        static::assertSame('CN=Leaf', $info->subject()->toString());
        static::assertTrue($info->validity()->permits(Timestamp::fromParts(150)));
    }

    public function test_it_exposes_the_issuer_serial_pair(): void
    {
        $issuerSerial = $this->info()->issuerSerial();

        static::assertSame('CN=Test CA', $issuerSerial->issuer->toString());
        static::assertSame('4242', $issuerSerial->serialNumber->toString());
    }

    public function test_it_exposes_the_subject_key_identifier(): void
    {
        static::assertSame(
            base64_encode("\x12\xAB\xCD"),
            $this->info()->subjectKeyIdentifier()->toBase64(),
        );
    }

    public function test_it_throws_when_the_subject_key_identifier_is_absent(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        $this->info(subjectKeyIdentifierHex: null)->subjectKeyIdentifier();
    }

    public function test_it_exposes_the_thumbprint(): void
    {
        $bytes = sha1('leaf', true);

        static::assertSame(
            base64_encode($bytes),
            $this->info(sha1Fingerprint: $bytes)->thumbprintSha1()->toBase64(),
        );
    }

    public function test_it_exposes_the_key_usage_or_null(): void
    {
        static::assertTrue($this->info()->keyUsage()?->permitsSigning());
        static::assertNull($this->info(keyUsageText: null)->keyUsage());
    }

    private function info(
        ?string $subjectKeyIdentifierHex = '12:AB:CD',
        ?string $keyUsageText = 'Digital Signature',
        ?string $sha1Fingerprint = null,
    ): CertificateInfo {
        return new CertificateInfo(
            DistinguishedName::fromStructured(['CN' => 'Leaf']),
            new IssuerSerial(DistinguishedName::fromStructured(['CN' => 'Test CA']), SerialNumber::fromDecimal('4242')),
            new ValidityWindow(Timestamp::fromParts(100), Timestamp::fromParts(200)),
            $subjectKeyIdentifierHex !== null ? SubjectKeyIdentifier::fromHex($subjectKeyIdentifierHex) : null,
            $keyUsageText !== null ? KeyUsage::fromExtension($keyUsageText) : null,
            Thumbprint::fromRawBytes($sha1Fingerprint ?? sha1('leaf', true)),
        );
    }
}
