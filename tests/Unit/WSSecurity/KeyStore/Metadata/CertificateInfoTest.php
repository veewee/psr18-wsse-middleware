<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore\Metadata;

use PHPUnit\Framework\TestCase;
use Psl\DateTime\Timestamp;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\CertificateInfo;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\ValidityWindow;

final class CertificateInfoTest extends TestCase
{
    public function test_it_exposes_the_subject_and_validity_window(): void
    {
        $info = $this->info();

        static::assertSame('CN=Leaf', $info->subject()->toString());
        static::assertTrue($info->validity()->permits(Timestamp::fromParts(150)));
    }

    public function test_it_builds_the_issuer_serial_pair(): void
    {
        $issuerSerial = $this->info()->issuerSerial();

        static::assertSame('CN=Test CA', $issuerSerial->issuer->toString());
        static::assertSame('4242', $issuerSerial->serialNumber);
    }

    public function test_it_builds_the_subject_key_identifier_from_its_hex(): void
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

    public function test_it_builds_the_thumbprint_from_the_fingerprint_bytes(): void
    {
        $bytes = sha1('leaf', true);

        static::assertSame(
            base64_encode($bytes),
            $this->info(sha1Fingerprint: $bytes)->thumbprintSha1()->toBase64(),
        );
    }

    public function test_it_returns_the_key_usage_or_null(): void
    {
        static::assertSame('Digital Signature', $this->info()->keyUsage());
        static::assertNull($this->info(keyUsage: null)->keyUsage());
    }

    private function info(
        ?string $subjectKeyIdentifierHex = '12:AB:CD',
        ?string $keyUsage = 'Digital Signature',
        ?string $sha1Fingerprint = null,
    ): CertificateInfo {
        return new CertificateInfo(
            DistinguishedName::fromStructured(['CN' => 'Leaf']),
            DistinguishedName::fromStructured(['CN' => 'Test CA']),
            '4242',
            new ValidityWindow(Timestamp::fromParts(100), Timestamp::fromParts(200)),
            $subjectKeyIdentifierHex,
            $keyUsage,
            $sha1Fingerprint ?? sha1('leaf', true),
        );
    }
}
