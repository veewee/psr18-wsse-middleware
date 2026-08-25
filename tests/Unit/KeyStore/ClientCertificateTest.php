<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\Pkcs12Bundle;
use SoapTest\Psr18WsseMiddleware\Unit\KeyStore\Fixture\Pkcs12Fixture;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;

final class ClientCertificateTest extends TestCase
{
    public function test_it_takes_the_certificate_and_key_from_a_pkcs12_bundle(): void
    {
        $clientCertificate = ClientCertificate::fromPkcs12(
            Pkcs12Bundle::fromString(Pkcs12Fixture::create('secret')->p12, 'secret'),
        );

        static::assertStringContainsString('PRIVATE KEY', $clientCertificate->privateKey()->contents());
        static::assertStringContainsString('CERTIFICATE', $clientCertificate->publicCertificate()->contents());
    }

    /**
     * A combined file may list its CA certificate ahead of the end-entity one, and exports made by hand
     * routinely do. Taking the first certificate in the file would then advertise the CA in the binary
     * security token while the message is signed with the leaf's key, so the leaf is derived from issuer
     * linkage instead of from position.
     */
    public function test_it_finds_the_leaf_wherever_the_bundle_lists_it(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $key = $fixture->leafKey->contents();
        $leaf = $fixture->leafCertificate->contents();
        $ca = $fixture->caCertificate->contents();

        $orderings = [
            'key, leaf, ca' => $key.$leaf.$ca,
            'ca, leaf, key' => $ca.$leaf.$key,
            'ca, key, leaf' => $ca.$key.$leaf,
        ];

        foreach ($orderings as $ordering => $bundle) {
            $subject = (new ClientCertificate($bundle))->publicCertificate()->info()->subject()->toString();

            static::assertStringContainsString(
                'WSSE Round Trip Leaf',
                $subject,
                "the end-entity certificate was not the one found in a bundle ordered: {$ordering}",
            );
        }
    }

    /**
     * Asking for the certificate must not fail over the key. Two keys in the file leave the identity
     * undecided, which privateKey() is entitled to refuse, but it says nothing about which certificate is the
     * end-entity one.
     */
    public function test_asking_for_the_certificate_does_not_fail_over_the_key_material(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $bundle = $fixture->caCertificate->contents().$fixture->leafCertificate->contents()
            .$fixture->leafKey->contents().WsseSignatureFixture::caSignedLeaf()->leafKey->contents();

        $subject = (new ClientCertificate($bundle))->publicCertificate()->info()->subject()->toString();

        static::assertStringContainsString('WSSE Round Trip Leaf', $subject);
    }

    /**
     * Two unrelated self-signed certificates each issued none of the others, so nothing says which key
     * signed. Choosing one would let the file decide what a signature is checked against, so the bundle is
     * refused instead.
     */
    public function test_it_refuses_a_bundle_with_no_single_end_entity_certificate(): void
    {
        $bundle = WsseSignatureFixture::selfSignedLeaf()->leafCertificate->contents()
            .WsseSignatureFixture::selfSignedLeaf()->leafCertificate->contents();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('no single end-entity');

        (new ClientCertificate($bundle))->publicCertificate();
    }

    public function test_it_reads_the_private_key_wherever_the_bundle_lists_it(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $bundle = $fixture->caCertificate->contents().$fixture->leafCertificate->contents()
            .$fixture->leafKey->contents();

        static::assertStringContainsString('PRIVATE KEY', (new ClientCertificate($bundle))->privateKey()->contents());
    }
}
