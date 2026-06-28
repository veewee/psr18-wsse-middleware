<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;

final class KeyTransportTest extends TestCase
{
    /**
     * @return array<string, array{0: KeyTransportAlgorithm}>
     */
    public static function methods(): array
    {
        return [
            'oaep-mgf1p' => [KeyTransportAlgorithm::legacyMgf1p()],
            'oaep-sha1' => [KeyTransportAlgorithm::oaepSha1()],
            'oaep-sha256' => [KeyTransportAlgorithm::oaepSha256()],
            'rsa-1_5' => [KeyTransportAlgorithm::rsa1_5()],
        ];
    }

    #[DataProvider('methods')]
    public function test_it_wraps_and_unwraps_a_session_key(KeyTransportAlgorithm $algorithm): void
    {
        $transport = new KeyTransport();
        [$private, $certificate] = $this->keyAndCertificate();
        $sessionKey = random_bytes(32);

        $wrapped = $transport->wrap($sessionKey, $certificate, $algorithm);

        static::assertNotSame($sessionKey, $wrapped);
        static::assertSame($sessionKey, $transport->unwrap($wrapped, $private, $algorithm));
    }

    public function test_unwrap_failures_are_uniform_regardless_of_padding(): void
    {
        $transport = new KeyTransport();
        [$private] = $this->keyAndCertificate();
        // An oversized "wrapped key" (larger than the modulus) always fails for any padding. Random bytes
        // sized to the modulus are NOT reliable: PKCS#1 v1.5 unpadding frequently accepts garbage (the
        // Bleichenbacher nature) and would spuriously "succeed" here.
        $garbage = random_bytes(512);

        $oaepSha1 = $this->captureFailureMessage($transport, $garbage, $private, KeyTransportAlgorithm::oaepSha1());
        $oaepSha256 = $this->captureFailureMessage($transport, $garbage, $private, KeyTransportAlgorithm::oaepSha256());
        $pkcs1 = $this->captureFailureMessage($transport, $garbage, $private, KeyTransportAlgorithm::rsa1_5());

        static::assertSame($oaepSha1, $pkcs1);
        static::assertSame($oaepSha256, $pkcs1);
    }

    private function captureFailureMessage(KeyTransport $transport, string $wrapped, Key $private, KeyTransportAlgorithm $algorithm): string
    {
        try {
            $transport->unwrap($wrapped, $private, $algorithm);
        } catch (CryptoOperationFailed $exception) {
            return $exception->getMessage();
        }

        static::fail('Expected a CryptoOperationFailed exception.');
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
