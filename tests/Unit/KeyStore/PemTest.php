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
    public function test_it_reads_the_private_key_out_of_a_combined_bundle(string $armor): void
    {
        $bundle = self::armored('anchor')."-----BEGIN {$armor}-----\nc2VjcmV0\n-----END {$armor}-----\n";

        $pem = Pem::fromString($bundle);

        static::assertCount(1, $pem->certificates());
        static::assertStringContainsString('c2VjcmV0', (string) $pem->privateKey()?->contents());
    }

    public function test_a_bundle_of_certificates_alone_carries_no_private_key(): void
    {
        static::assertNull(Pem::fromString(self::armored('anchor-a').self::armored('anchor-b'))->privateKey());
    }

    /**
     * The reason the bundle string stays safe to hand to openssl's path-based APIs: it is rebuilt from the
     * certificates alone, so a combined file's key never reaches the temp file toResource() writes.
     */
    public function test_it_keeps_key_material_out_of_the_bundle_string(): void
    {
        $pem = Pem::fromString(
            self::armored('anchor')."-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n",
        );

        // Held in a variable: the temp file is unlinked once the stream goes out of scope.
        $resource = $pem->toResource();

        static::assertStringNotContainsString('c2VjcmV0', $pem->toString());
        static::assertStringNotContainsString('PRIVATE KEY', $pem->toString());
        static::assertStringNotContainsString('c2VjcmV0', (string) file_get_contents((string) $resource->uri()));
    }

    /**
     * Two keys in one file leave nothing to say which identity is yours, and picking the first would let the
     * file's layout decide what a message is signed with.
     */
    public function test_it_refuses_a_bundle_carrying_more_than_one_private_key(): void
    {
        $bundle = self::armored('anchor')
            ."-----BEGIN PRIVATE KEY-----\nZmlyc3Q=\n-----END PRIVATE KEY-----\n"
            ."-----BEGIN PRIVATE KEY-----\nc2Vjb25k\n-----END PRIVATE KEY-----\n";

        $this->expectException(InvalidPemBundle::class);
        $this->expectExceptionMessage('more than one private key');

        Pem::fromString($bundle);
    }

    /**
     * The same argument as an unclosed certificate: a half-transferred file must not load as the part that
     * survived, which here would be an identity bundle quietly missing its key.
     */
    public function test_it_refuses_a_bundle_whose_private_key_is_unclosed(): void
    {
        $bundle = self::armored('anchor')."-----BEGIN PRIVATE KEY-----\nY3V0LW9mZg==";

        $this->expectException(InvalidPemBundle::class);
        $this->expectExceptionMessage('truncated');

        Pem::fromString($bundle);
    }

    /**
     * A key block sitting inside certificate armor is not a certificate. The certificate pattern ends at the
     * first closing line, so reading the outer block whole would fold the key into the bundle string, and from
     * there into the temp file toResource() writes.
     */
    public function test_it_refuses_a_certificate_block_with_armor_nested_inside_it(): void
    {
        $bundle = "-----BEGIN CERTIFICATE-----\n".base64_encode('cert')."\n"
            ."-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n"
            ."-----END CERTIFICATE-----\n";

        $this->expectException(InvalidPemBundle::class);
        $this->expectExceptionMessage('nested');

        Pem::fromString($bundle);
    }

    /**
     * The mirror of the certificate case, and it must be refused for the same reason: the key pattern also
     * stops at the first matching close, so a certificate wrapped in key armor would be handed back as part
     * of the key. The opening counts agree here, so the truncation check cannot catch this one.
     */
    public function test_it_refuses_a_private_key_block_with_armor_nested_inside_it(): void
    {
        $bundle = "-----BEGIN PRIVATE KEY-----\n".base64_encode('key')."\n"
            .self::armored('smuggled')
            ."-----END PRIVATE KEY-----\n";

        $this->expectException(InvalidPemBundle::class);
        $this->expectExceptionMessage('nested');

        Pem::fromString($bundle);
    }

    /**
     * An opening and a closing line that name different key types are not a block. Reading to the end of the
     * mismatched pair would take in whatever sat between them.
     */
    public function test_it_refuses_a_private_key_whose_armor_lines_disagree(): void
    {
        $bundle = self::armored('anchor')."-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END RSA PRIVATE KEY-----\n";

        $this->expectException(InvalidPemBundle::class);
        $this->expectExceptionMessage('truncated');

        Pem::fromString($bundle);
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

    /**
     * Reading the certificates is a separate question from whether the key material alongside them makes
     * sense, and a caller that only wants the certificates must not be handed a failure about the key.
     */
    public function test_it_reads_the_certificates_without_judging_the_key_material(): void
    {
        $bundle = self::armored('anchor')
            ."-----BEGIN PRIVATE KEY-----\nZmlyc3Q=\n-----END PRIVATE KEY-----\n"
            ."-----BEGIN PRIVATE KEY-----\nc2Vjb25k\n-----END PRIVATE KEY-----\n";

        static::assertCount(1, Pem::certificatesIn($bundle));
    }

    private static function armored(string $body): string
    {
        return "-----BEGIN CERTIFICATE-----\n".base64_encode($body)."\n-----END CERTIFICATE-----\n";
    }
}
