<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Parser;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\ParsedCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;

final class ParsedCertificateTest extends TestCase
{
    public function test_it_exposes_the_typed_fields_of_a_certificate(): void
    {
        $certificate = $this->certificate(4242, "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\nsubjectKeyIdentifier = hash\nkeyUsage = digitalSignature\n");

        $parsed = ParsedCertificate::fromCertificate($certificate);

        static::assertStringContainsString('Parsed Cert Subject', $parsed->subjectName());
        static::assertNotEmpty($parsed->issuer());
        static::assertSame('4242', $parsed->serialNumberRaw());
        static::assertGreaterThan(0, $parsed->validFrom());
        static::assertGreaterThan($parsed->validFrom(), $parsed->validTo());
        static::assertNotNull($parsed->subjectKeyIdentifierHex());
        static::assertStringContainsString('Digital Signature', (string) $parsed->keyUsage());

        $expectedFingerprint = (string) openssl_x509_fingerprint($certificate->contents(), 'sha1', true);
        static::assertSame($expectedFingerprint, $parsed->sha1Fingerprint());
    }

    public function test_it_returns_null_for_absent_optional_extensions(): void
    {
        $certificate = $this->certificate(7, "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\n");

        $parsed = ParsedCertificate::fromCertificate($certificate);

        static::assertNull($parsed->subjectKeyIdentifierHex());
        static::assertNull($parsed->keyUsage());
    }

    public function test_it_runs_the_openssl_boundary_once_per_instance(): void
    {
        // A second read off the same instance returns the cached fields rather than re-parsing.
        $certificate = $this->certificate(1, "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\nsubjectKeyIdentifier = hash\n");

        $parsed = ParsedCertificate::fromCertificate($certificate);

        static::assertSame($parsed->serialNumberRaw(), $parsed->serialNumberRaw());
        static::assertSame($parsed->subjectName(), $parsed->subjectName());
    }

    public function test_it_throws_on_an_unparseable_certificate(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        ParsedCertificate::fromCertificate(new Certificate('not-a-certificate'));
    }

    private function certificate(int $serial, string $configContents): Certificate
    {
        $config = ['config' => $this->configFile($configContents)];

        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA] + $config);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);

        $csr = openssl_csr_new(['commonName' => 'Parsed Cert Subject'], $private, $config);
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
