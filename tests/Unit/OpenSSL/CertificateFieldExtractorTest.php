<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL;

use phpseclib3\Math\BigInteger;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateFieldExtractor;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;

final class CertificateFieldExtractorTest extends TestCase
{
    public function test_it_extracts_the_subject_key_identifier_as_base64(): void
    {
        $certificate = $this->certificateWithSki();

        $ski = (new CertificateFieldExtractor())->subjectKeyIdentifier($certificate);

        // The base64 must decode to the raw bytes of the colon-separated hex in the SKI extension.
        static::assertSame($this->expectedSkiBase64($certificate), $ski);
        static::assertNotFalse(base64_decode($ski, true));
    }

    public function test_it_throws_when_the_certificate_lacks_a_subject_key_identifier(): void
    {
        $certificate = $this->certificateWithoutSki();

        $this->expectException(CryptoOperationFailed::class);
        (new CertificateFieldExtractor())->subjectKeyIdentifier($certificate);
    }

    public function test_it_extracts_the_issuer_name_and_serial_number(): void
    {
        $leaf = $this->caSignedLeaf(1234567890);

        $issuerSerial = (new CertificateFieldExtractor())->issuerSerial($leaf);

        // The issuer name is the CA distinguished name in RFC 2253 form: no leading slash, comma separated,
        // most-specific RDN first. It must be the issuer (the CA), not the leaf subject.
        static::assertSame(
            'CN=Field Extractor Test CA,O=PHPro,C=BE',
            $issuerSerial['issuerName'],
        );
        static::assertStringStartsNotWith('/', $issuerSerial['issuerName']);
        static::assertStringNotContainsString('Leaf Subject', $issuerSerial['issuerName']);

        // The serial is a decimal integer string, never hex.
        static::assertSame('1234567890', $issuerSerial['serialNumber']);
        static::assertMatchesRegularExpression('/^\d+$/', $issuerSerial['serialNumber']);
    }

    public function test_it_renders_a_serial_beyond_the_php_integer_range_as_decimal(): void
    {
        // A 20-byte serial exceeds the platform integer range and must round-trip without precision loss.
        $serial = '143266986699850468079199010478798978082';
        $leaf = $this->caSignedLeaf($serial);

        $issuerSerial = (new CertificateFieldExtractor())->issuerSerial($leaf);

        static::assertSame($serial, $issuerSerial['serialNumber']);
        static::assertMatchesRegularExpression('/^\d+$/', $issuerSerial['serialNumber']);
    }

    public function test_it_extracts_the_sha1_thumbprint_as_base64(): void
    {
        $certificate = $this->certificateWithSki();

        $thumbprint = (new CertificateFieldExtractor())->thumbprintSha1($certificate);

        $expected = base64_encode((string) openssl_x509_fingerprint($certificate->contents(), 'sha1', true));
        static::assertSame($expected, $thumbprint);
    }

    public function test_it_throws_on_an_unparseable_certificate_for_every_method(): void
    {
        $extractor = new CertificateFieldExtractor();
        $garbage = new Certificate('not-a-certificate');

        foreach (['subjectKeyIdentifier', 'issuerSerial', 'thumbprintSha1'] as $method) {
            try {
                $extractor->{$method}($garbage);
                static::fail(sprintf('%s did not throw on an unparseable certificate.', $method));
            } catch (CryptoOperationFailed) {
                $this->addToAssertionCount(1);
            }
        }
    }

    private function expectedSkiBase64(Certificate $certificate): string
    {
        $info = openssl_x509_parse($certificate->contents());
        static::assertIsArray($info);
        static::assertIsArray($info['extensions']);
        $hex = $info['extensions']['subjectKeyIdentifier'];
        static::assertIsString($hex);

        return base64_encode((string) hex2bin(str_replace(':', '', $hex)));
    }

    private function certificateWithSki(): Certificate
    {
        $config = $this->opensslConfig("[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\nsubjectKeyIdentifier = hash\n");

        return $this->signedCertificate('field-extractor-test', $config, 1);
    }

    /**
     * A leaf certificate signed by a separate CA, so the subject and issuer differ. The CA distinguished name
     * carries country, organisation and common name so the RFC 2253 ordering and escaping can be asserted.
     *
     * @param int|numeric-string $serial
     */
    private function caSignedLeaf(int|string $serial): Certificate
    {
        // An empty distinguished-name section keeps the issuer free of the openssl default fields, so the
        // RFC 2253 ordering can be asserted against exactly the names set here.
        $config = $this->opensslConfig("[req]\ndistinguished_name = dn\n[dn]\n");

        $caKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA] + $config);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $caKey);

        $caCsr = openssl_csr_new(
            ['countryName' => 'BE', 'organizationName' => 'PHPro', 'commonName' => 'Field Extractor Test CA'],
            $caKey,
            $config,
        );
        static::assertNotFalse($caCsr);

        $caCert = openssl_csr_sign($caCsr, null, $caKey, 3650, $config + ['digest_alg' => 'sha256']);
        static::assertNotFalse($caCert);

        $leafKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA] + $config);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $leafKey);

        $leafCsr = openssl_csr_new(['commonName' => 'Leaf Subject'], $leafKey, $config);
        static::assertNotFalse($leafCsr);

        $leafCert = $this->signLeaf($leafCsr, $caCert, $caKey, $config, $serial);

        static::assertTrue(openssl_x509_export($leafCert, $leafPem));
        static::assertIsString($leafPem);

        return new Certificate($leafPem);
    }

    /**
     * @param array{config: non-empty-string} $config
     * @param int|numeric-string              $serial
     */
    private function signLeaf(OpenSSLCertificateSigningRequest $csr, OpenSSLCertificate $caCert, OpenSSLAsymmetricKey $caKey, array $config, int|string $serial): OpenSSLCertificate
    {
        // Serials beyond the platform integer range are passed through the hexadecimal parameter, since the
        // integer serial argument cannot carry them.
        if (is_string($serial)) {
            $cert = openssl_csr_sign($csr, $caCert, $caKey, 365, $config + ['digest_alg' => 'sha256'], 0, (new BigInteger($serial, 10))->toHex());
        } else {
            $cert = openssl_csr_sign($csr, $caCert, $caKey, 365, $config + ['digest_alg' => 'sha256'], $serial);
        }

        static::assertNotFalse($cert);

        return $cert;
    }

    private function certificateWithoutSki(): Certificate
    {
        $config = $this->opensslConfig("[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\n");

        return $this->signedCertificate('no-ski', $config, 1);
    }

    /**
     * @return array{config: non-empty-string}
     */
    private function opensslConfig(string $contents): array
    {
        $path = tempnam(sys_get_temp_dir(), 'wsse-ossl-');
        static::assertIsString($path);
        file_put_contents($path, $contents);

        return ['config' => $path];
    }

    /**
     * @param array{config: non-empty-string} $config
     */
    private function signedCertificate(string $commonName, array $config, int $serial): Certificate
    {
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA] + $config);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);

        $csr = openssl_csr_new(['commonName' => $commonName], $private, $config);
        static::assertNotFalse($csr);

        $certificate = openssl_csr_sign($csr, null, $private, 365, $config + ['x509_extensions' => 'v3'], $serial);
        static::assertNotFalse($certificate);

        static::assertTrue(openssl_x509_export($certificate, $certificatePem));
        static::assertIsString($certificatePem);

        return new Certificate($certificatePem);
    }
}
