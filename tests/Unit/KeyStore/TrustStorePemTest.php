<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore;

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

    private static function armored(string $body): string
    {
        return "-----BEGIN CERTIFICATE-----\n".base64_encode($body)."\n-----END CERTIFICATE-----\n";
    }
}
