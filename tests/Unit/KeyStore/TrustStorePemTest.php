<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore;

use PHPUnit\Framework\Attributes\DataProviderExternal;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidTrustStore;
use Soap\Psr18WsseMiddleware\KeyStore\Pem;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;

final class TrustStorePemTest extends TestCase
{
    /**
     * Every entry of a converted Java truststore is an anchor, so none may be treated as an end-entity
     * certificate and dropped. A store built from three certificates holds three anchors, not two.
     */
    public function test_it_makes_every_certificate_in_the_bundle_an_anchor(): void
    {
        $bundle = Pem::fromString(self::armored('anchor-a').self::armored('anchor-b').self::armored('anchor-c'));

        $trustStore = TrustStore::fromPem($bundle);

        static::assertCount(3, $trustStore->anchors());
        static::assertStringContainsString(base64_encode('anchor-a'), $trustStore->anchors()[0]->contents());
        static::assertStringContainsString(base64_encode('anchor-c'), $trustStore->anchors()[2]->contents());
    }

    public function test_it_rejects_a_bundle_without_a_certificate(): void
    {
        $this->expectException(InvalidTrustStore::class);
        $this->expectExceptionMessage('at least one trust anchor');

        TrustStore::fromPem(Pem::fromCertificates());
    }

    /**
     * A trust store holds public certificates only. Key material in a file destined for one means the wrong
     * file was exported, so it is refused rather than silently ignored. The bundle itself reads a combined
     * file happily; deciding that a key has no business in a trust store is this method's job, not the
     * reader's.
     */
    #[DataProviderExternal(PemTest::class, 'privateKeyArmor')]
    public function test_it_rejects_a_bundle_carrying_private_key_material(string $armor): void
    {
        $bundle = Pem::fromString(
            self::armored('anchor')."-----BEGIN {$armor}-----\nc2VjcmV0\n-----END {$armor}-----\n",
        );

        $this->expectException(InvalidTrustStore::class);
        $this->expectExceptionMessage('public certificates only');

        TrustStore::fromPem($bundle);
    }

    /**
     * Refusing the file is only half the job: a caller who lands here reached for the wrong file, so the
     * message has to say which class takes a combined certificate-and-key one.
     */
    public function test_it_points_a_rejected_key_bearing_bundle_at_the_right_class(): void
    {
        $bundle = Pem::fromString(
            self::armored('anchor')."-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n",
        );

        try {
            TrustStore::fromPem($bundle);
            static::fail('a bundle carrying private key material should not build a trust store');
        } catch (InvalidTrustStore $e) {
            static::assertStringContainsString('ClientCertificate', $e->getMessage());
            static::assertStringContainsString('Key', $e->getMessage());
        }
    }

    private static function armored(string $body): string
    {
        return "-----BEGIN CERTIFICATE-----\n".base64_encode($body)."\n-----END CERTIFICATE-----\n";
    }
}
