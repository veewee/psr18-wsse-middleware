<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;

final class SignerTest extends TestCase
{
    public function test_it_signs_and_verifies_with_every_rsa_method(): void
    {
        $signer = new Signer();
        [$private, $certificate] = $this->keyAndCertificate();
        $data = 'the canonicalized SignedInfo';

        foreach ([SignatureMethod::RSA_SHA1, SignatureMethod::RSA_SHA256, SignatureMethod::RSA_SHA384, SignatureMethod::RSA_SHA512] as $method) {
            $signature = $signer->sign($private, $data, $method);

            static::assertNotSame('', $signature);
            static::assertTrue($signer->verify($certificate, $data, $signature, $method));
        }
    }

    public function test_verify_fails_for_tampered_data(): void
    {
        $signer = new Signer();
        [$private, $certificate] = $this->keyAndCertificate();

        $signature = $signer->sign($private, 'original', SignatureMethod::RSA_SHA256);

        static::assertFalse($signer->verify($certificate, 'tampered', $signature, SignatureMethod::RSA_SHA256));
    }

    public function test_verify_fails_for_a_different_key(): void
    {
        $signer = new Signer();
        [$private] = $this->keyAndCertificate();
        [, $otherCertificate] = $this->keyAndCertificate();

        $signature = $signer->sign($private, 'payload', SignatureMethod::RSA_SHA256);

        static::assertFalse($signer->verify($otherCertificate, 'payload', $signature, SignatureMethod::RSA_SHA256));
    }

    public function test_verify_fails_when_the_methods_digest_differs(): void
    {
        $signer = new Signer();
        [$private, $certificate] = $this->keyAndCertificate();

        $signature = $signer->sign($private, 'payload', SignatureMethod::RSA_SHA256);

        static::assertFalse($signer->verify($certificate, 'payload', $signature, SignatureMethod::RSA_SHA512));
    }

    public function test_a_malformed_signature_is_rejected_and_never_treated_as_valid(): void
    {
        $signer = new Signer();
        [, $certificate] = $this->keyAndCertificate();

        // A garbage signature must come back as a strict false, never a truthy result (the xmlseclibs
        // -1->true forgery trap), and without distinguishing "malformed" from "invalid".
        static::assertFalse($signer->verify($certificate, 'payload', 'not-a-real-signature', SignatureMethod::RSA_SHA256));
        static::assertFalse($signer->verify($certificate, 'payload', '', SignatureMethod::RSA_SHA256));
        static::assertFalse($signer->verify($certificate, 'payload', str_repeat('A', 5000), SignatureMethod::RSA_SHA256));
    }

    public function test_signing_fails_when_the_key_is_not_a_private_key(): void
    {
        $signer = new Signer();
        [, $certificate] = $this->keyAndCertificate();

        // A certificate PEM carries no private key, so resolving it for signing fails. The key is our own
        // (a non-oracle path), so the real reason surfaces as OpenSslException.
        $this->expectException(OpenSslException::class);
        $signer->sign(new Key($certificate->contents()), 'payload', SignatureMethod::RSA_SHA256);
    }

    /**
     * Every signature method the enum advertises must be executable by the signer: none may map to an
     * unsupported algorithm. This guards the enum against re-introducing a case the engine cannot apply.
     */
    public function test_every_signature_method_is_executable(): void
    {
        $signer = new Signer();
        [$private] = $this->keyAndCertificate();

        foreach (SignatureMethod::cases() as $method) {
            $signature = $signer->sign($private, 'payload', $method);
            static::assertNotSame('', $signature);
        }
    }

    /**
     * @return array{0: Key, 1: Certificate}
     */
    private function keyAndCertificate(): array
    {
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);

        static::assertTrue(openssl_pkey_export($private, $privatePem));
        static::assertIsString($privatePem);

        $csr = openssl_csr_new(['commonName' => 'wsse-test'], $private);
        static::assertNotFalse($csr);

        $certificate = openssl_csr_sign($csr, null, $private, 365);
        static::assertNotFalse($certificate);

        static::assertTrue(openssl_x509_export($certificate, $certificatePem));
        static::assertIsString($certificatePem);

        return [new Key($privatePem), new Certificate($certificatePem)];
    }
}
