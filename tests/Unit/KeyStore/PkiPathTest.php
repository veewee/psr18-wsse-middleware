<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\PkiPath;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;

/**
 * A PKIPath token body is an ASN.1 SEQUENCE OF Certificate, which the WS-Security X.509 Token Profile
 * recommends over PKCS#7 for carrying a certification path. Only the outer SEQUENCE is unwrapped here: each
 * inner element is handed on as its own DER certificate, and the order is left to the caller to interpret
 * because the profile's two path token types disagree about whether order means anything.
 *
 * The bytes arrive from an unauthenticated peer, so every declared length is bounds-checked against what the
 * input actually holds rather than trusted.
 */
final class PkiPathTest extends TestCase
{
    public function test_it_unwraps_a_two_certificate_path(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $leaf = $this->der($fixture->certificateBase64Der($fixture->leafCertificate));
        $ca = $this->der($fixture->certificateBase64Der($fixture->caCertificate));

        $certificates = PkiPath::certificates($this->derSequence($ca, $leaf));

        static::assertCount(2, $certificates);
        // Handed back in the order they appeared; interpreting that order is not this parser's job.
        static::assertSame($ca, $this->der($certificates[0]->toBase64Der()));
        static::assertSame($leaf, $this->der($certificates[1]->toBase64Der()));
    }

    public function test_it_unwraps_a_single_certificate_path(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $leaf = $this->der($fixture->certificateBase64Der($fixture->leafCertificate));

        $certificates = PkiPath::certificates($this->derSequence($leaf));

        static::assertCount(1, $certificates);
        static::assertSame($leaf, $this->der($certificates[0]->toBase64Der()));
    }

    public function test_it_encodes_a_path_from_the_trust_anchor_down_to_the_end_entity(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $leaf = $this->der($fixture->certificateBase64Der($fixture->leafCertificate));
        $ca = $this->der($fixture->certificateBase64Der($fixture->caCertificate));

        $der = PkiPath::encode(CertificateChain::fromCertificates($fixture->leafCertificate, $fixture->caCertificate));

        // The chain is leaf first; a PkiPath is anchor first, so the encoder emits it the other way round.
        static::assertSame($this->derSequence($ca, $leaf), $der);
    }

    public function test_it_encodes_a_single_certificate_path(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $leaf = $this->der($fixture->certificateBase64Der($fixture->leafCertificate));

        $der = PkiPath::encode(CertificateChain::fromCertificates($fixture->leafCertificate));

        static::assertSame($this->derSequence($leaf), $der);
    }

    public function test_it_refuses_bytes_that_are_not_a_sequence(): void
    {
        // 0x04 is OCTET STRING, not SEQUENCE.
        $this->expectException(InvalidCertificate::class);
        PkiPath::certificates("\x04\x03abc");
    }

    public function test_it_refuses_an_element_whose_length_runs_past_the_input(): void
    {
        // A SEQUENCE declaring one 200-byte element while carrying three bytes.
        $this->expectException(InvalidCertificate::class);
        PkiPath::certificates("\x30\x05\x30\x81\xc8ab");
    }

    public function test_it_refuses_an_element_that_is_not_a_sequence(): void
    {
        // A certificate is a SEQUENCE. Without this check the walker hands back a Certificate wrapping any
        // bytes at all, because base64-to-PEM does not parse: the garbage would only surface later, at the
        // trust check, or not at all for a single-element path that skips the ordering step.
        $this->expectException(InvalidCertificate::class);
        PkiPath::certificates($this->derSequence("\x04\x01a"));
    }

    public function test_it_refuses_a_zero_length_element(): void
    {
        // An empty SEQUENCE cannot be a certificate, and 4000 of them cost nothing to send.
        $this->expectException(InvalidCertificate::class);
        PkiPath::certificates($this->derSequence("\x30\x00"));
    }

    public function test_it_refuses_an_empty_path(): void
    {
        $this->expectException(InvalidCertificate::class);
        PkiPath::certificates($this->derSequence());
    }

    /**
     * Wraps the given DER elements in an ASN.1 SEQUENCE, with the length encoded by hand so the expectation
     * never depends on the parser under test.
     */
    private function derSequence(string ...$elements): string
    {
        $body = implode('', $elements);
        $length = strlen($body);

        if ($length < 0x80) {
            $header = chr($length);
        } else {
            $bytes = '';
            for ($remaining = $length; $remaining > 0; $remaining >>= 8) {
                $bytes = chr($remaining & 0xFF).$bytes;
            }
            $header = chr(0x80 | strlen($bytes)).$bytes;
        }

        return "\x30".$header.$body;
    }

    private function der(string $base64Der): string
    {
        return (string) base64_decode($base64Der, true);
    }
}
