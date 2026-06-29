<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Parser;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use Psl\DateTime\Timestamp;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\CertificateInfoParser;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\CertificateInfo;

final class CertificateInfoParserTest extends TestCase
{
    public function test_it_builds_the_certificate_info_value_objects(): void
    {
        $certificate = $this->certificate(4242, "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\nsubjectKeyIdentifier = hash\nkeyUsage = digitalSignature\n");

        $info = (new CertificateInfoParser())->parse($certificate);

        static::assertStringContainsString('CertificateInfo Subject', $info->subject()->toString());
        static::assertSame('4242', $info->issuerSerial()->serialNumber);
        static::assertStringContainsString('CertificateInfo Subject', $info->issuerSerial()->issuer->toString());
        static::assertTrue($info->validity()->permits(Timestamp::now()));
        static::assertNotSame('', $info->subjectKeyIdentifier()->toBase64());
        static::assertStringContainsString('Digital Signature', (string) $info->keyUsage());

        $expected = base64_encode((string) openssl_x509_fingerprint($certificate->contents(), 'sha1', true));
        static::assertSame($expected, $info->thumbprintSha1()->toBase64());
    }

    public function test_it_leaves_absent_optional_extensions_unset(): void
    {
        $certificate = $this->certificate(7, "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\n");

        $info = (new CertificateInfoParser())->parse($certificate);

        static::assertNull($info->keyUsage());
        $this->expectException(CryptoOperationFailed::class);
        $info->subjectKeyIdentifier();
    }

    public function test_certificate_info_can_be_built_straight_from_a_certificate(): void
    {
        $certificate = $this->certificate(99, "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\n");

        $info = CertificateInfo::fromCertificate($certificate);

        static::assertStringContainsString('CertificateInfo Subject', $info->subject()->toString());
        static::assertSame('99', $info->issuerSerial()->serialNumber);
    }

    public function test_it_throws_on_an_unparseable_certificate(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        (new CertificateInfoParser())->parse(new Certificate('not-a-certificate'));
    }

    private function certificate(int $serial, string $configContents): Certificate
    {
        $config = ['config' => $this->configFile($configContents)];

        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA] + $config);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);

        $csr = openssl_csr_new(['commonName' => 'CertificateInfo Subject'], $private, $config);
        static::assertNotFalse($csr);

        $certificate = openssl_csr_sign($csr, null, $private, 365, $config + ['x509_extensions' => 'v3'], $serial);
        static::assertNotFalse($certificate);

        static::assertTrue(openssl_x509_export($certificate, $pem));
        static::assertIsString($pem);

        return new Certificate($pem);
    }

    private function configFile(string $contents): string
    {
        $path = tempnam(sys_get_temp_dir(), 'wsse-ossl-');
        static::assertIsString($path);
        file_put_contents($path, $contents);

        return $path;
    }
}
