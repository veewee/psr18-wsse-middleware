<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidPemBundle;
use Soap\Psr18WsseMiddleware\KeyStore\Pem;

final class PemTest extends TestCase
{
    public function test_it_concatenates_certificates_into_one_bundle(): void
    {
        $pem = Pem::fromCertificates(new Certificate('first-pem'), new Certificate('second-pem'));

        static::assertStringContainsString('first-pem', $pem->toString());
        static::assertStringContainsString('second-pem', $pem->toString());
    }

    public function test_it_writes_itself_to_a_readable_temp_file(): void
    {
        $resource = Pem::fromCertificates(new Certificate('cert-bytes'))->toResource();

        static::assertSame('cert-bytes', (string) file_get_contents((string) $resource->uri()));
    }

    public function test_it_reads_every_concatenated_certificate_back_out(): void
    {
        $pem = Pem::fromString(self::armored('first').self::armored('second').self::armored('third'));

        static::assertCount(3, $pem->certificates());
        static::assertStringContainsString(base64_encode('first'), $pem->certificates()[0]->contents());
        static::assertStringContainsString(base64_encode('second'), $pem->certificates()[1]->contents());
        static::assertStringContainsString(base64_encode('third'), $pem->certificates()[2]->contents());
    }

    /**
     * The shape `openssl pkcs12 -nokeys` emits: each certificate preceded by bag attributes and a subject and
     * issuer line. Those must not be mistaken for certificate content, nor stop the bundle from being read.
     */
    public function test_it_ignores_the_metadata_openssl_writes_around_each_certificate(): void
    {
        $bundle = "Bag Attributes: <No Attributes>\nsubject=CN=anchor-a\nissuer=CN=anchor-a\n"
            .self::armored('anchor-a')
            ."Bag Attributes: <No Attributes>\nsubject=CN=anchor-b\nissuer=CN=anchor-b\n"
            .self::armored('anchor-b');

        $pem = Pem::fromString($bundle);

        static::assertCount(2, $pem->certificates());
        static::assertStringNotContainsString('Bag Attributes', $pem->toString());
        static::assertStringNotContainsString('subject=', $pem->toString());
    }

    public function test_it_reads_a_bundle_from_a_file(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'wsse-pem-');
        if ($file === false) {
            throw new RuntimeException('Unable to create the bundle fixture file.');
        }
        file_put_contents($file, self::armored('from-disk'));

        try {
            static::assertCount(1, Pem::fromFile($file)->certificates());
        } finally {
            unlink($file);
        }
    }

    public function test_it_rejects_a_bundle_holding_no_certificate(): void
    {
        $this->expectException(InvalidPemBundle::class);
        $this->expectExceptionMessage('does not contain a PEM certificate');

        Pem::fromString('subject=CN=anchor-a'."\n".'issuer=CN=anchor-a');
    }

    #[DataProvider('privateKeyArmor')]
    public function test_it_rejects_a_bundle_carrying_private_key_material(string $armor): void
    {
        $bundle = self::armored('anchor')."-----BEGIN {$armor}-----\nc2VjcmV0\n-----END {$armor}-----\n";

        $this->expectException(InvalidPemBundle::class);
        $this->expectExceptionMessage('public certificates only');

        Pem::fromString($bundle);
    }

    /**
     * Refusing the file is only half the job: a caller who lands here reached for the wrong class, so the
     * message has to say which one takes a combined certificate-and-key file.
     */
    public function test_it_points_a_rejected_key_bearing_bundle_at_the_right_class(): void
    {
        try {
            Pem::fromString(self::armored('anchor')."-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n");
            static::fail('a bundle carrying private key material should not load');
        } catch (InvalidPemBundle $e) {
            static::assertStringContainsString('ClientCertificate', $e->getMessage());
            static::assertStringContainsString('Key', $e->getMessage());
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function privateKeyArmor(): iterable
    {
        yield 'pkcs#8' => ['PRIVATE KEY'];
        yield 'encrypted pkcs#8' => ['ENCRYPTED PRIVATE KEY'];
        yield 'pkcs#1 rsa' => ['RSA PRIVATE KEY'];
        yield 'sec1 ec' => ['EC PRIVATE KEY'];
        yield 'openssh' => ['OPENSSH PRIVATE KEY'];
        // A label may carry a suffix as well as a prefix, so matching only up to "PRIVATE KEY" lets this through.
        yield 'pgp block' => ['PGP PRIVATE KEY BLOCK'];
    }

    /**
     * A half-written or half-transferred bundle must not load as the anchors that did survive. Dropping the
     * unclosed one silently is the failure this whole loading path exists to prevent.
     */
    public function test_it_refuses_a_bundle_whose_last_certificate_is_unclosed(): void
    {
        $bundle = self::armored('anchor-a').self::armored('anchor-b')
            ."-----BEGIN CERTIFICATE-----\n".base64_encode('cut-off-mid-transfer');

        $this->expectException(InvalidPemBundle::class);
        $this->expectExceptionMessage('truncated');

        Pem::fromString($bundle);
    }

    public function test_it_reports_a_single_unclosed_certificate_as_truncated_rather_than_absent(): void
    {
        $this->expectException(InvalidPemBundle::class);
        $this->expectExceptionMessage('truncated');

        Pem::fromString("-----BEGIN CERTIFICATE-----\n".base64_encode('only-one-and-cut-off'));
    }

    /**
     * Bundles exported on Windows, and by Java tooling, routinely carry CRLF line endings.
     */
    public function test_it_reads_a_bundle_with_windows_line_endings(): void
    {
        $crlf = str_replace("\n", "\r\n", self::armored('anchor-a').self::armored('anchor-b'));

        static::assertCount(2, Pem::fromString($crlf)->certificates());
    }

    public function test_a_bundle_it_parsed_round_trips_through_its_own_string(): void
    {
        $once = Pem::fromString(self::armored('first').self::armored('second'));
        $twice = Pem::fromString($once->toString());

        static::assertSame($once->toString(), $twice->toString());
        static::assertCount(2, $twice->certificates());
    }

    private static function armored(string $body): string
    {
        return "-----BEGIN CERTIFICATE-----\n".base64_encode($body)."\n-----END CERTIFICATE-----\n";
    }
}
