<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Internal;

use OpenSSLAsymmetricKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey as PhpseclibPrivateKey;
use phpseclib3\Crypt\RSA\PublicKey as PhpseclibPublicKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;

/**
 * Differential test of our OAEP key transport against the audited phpseclib OAEP, both directions and both
 * hashes. phpseclib is the independent oracle: anything our hand-rolled EME-OAEP encodes must decrypt under
 * phpseclib byte for byte, and anything phpseclib encrypts must unwrap under ours, proving interoperability
 * with a second implementation rather than just self-consistency.
 */
final class OaepPhpseclibCrossTest extends TestCase
{
    private Key $key;
    private Certificate $certificate;
    private PhpseclibPrivateKey $phpseclibPrivate;
    private PhpseclibPublicKey $phpseclibPublic;

    protected function setUp(): void
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $resource);

        static::assertTrue(openssl_pkey_export($resource, $privatePem));
        static::assertIsString($privatePem);

        $csr = openssl_csr_new(['commonName' => 'wsse-cross'], $resource);
        static::assertNotFalse($csr);
        $signed = openssl_csr_sign($csr, null, $resource, 365);
        static::assertNotFalse($signed);
        static::assertTrue(openssl_x509_export($signed, $certificatePem));
        static::assertIsString($certificatePem);

        $this->key = new Key($privatePem);
        $this->certificate = new Certificate($certificatePem);

        $private = PublicKeyLoader::load($privatePem);
        static::assertInstanceOf(PhpseclibPrivateKey::class, $private);
        $this->phpseclibPrivate = $private;
        $this->phpseclibPublic = $private->getPublicKey();
    }

    /**
     * @return array<string, array{0: KeyTransportAlgorithm, 1: 'sha1'|'sha256', 2: int}>
     */
    public static function casesProvider(): array
    {
        $cases = [];
        foreach (['sha1' => KeyTransportAlgorithm::oaepSha1(), 'sha256' => KeyTransportAlgorithm::oaepSha256()] as $hash => $algorithm) {
            foreach ([16, 24, 32] as $size) {
                $cases["{$hash}-{$size}"] = [$algorithm, $hash, $size];
            }
        }

        return $cases;
    }

    /**
     * @param 'sha1'|'sha256' $hash
     */
    #[DataProvider('casesProvider')]
    public function test_our_wrap_is_decrypted_by_phpseclib(KeyTransportAlgorithm $algorithm, string $hash, int $size): void
    {
        $sessionKey = random_bytes($size);

        $wrapped = (new KeyTransport())->wrap($sessionKey, $this->certificate, $algorithm);

        static::assertSame($sessionKey, $this->phpseclibPrivate->withPadding(RSA::ENCRYPTION_OAEP)->withHash($hash)->withMGFHash($hash)->decrypt($wrapped));
    }

    /**
     * @param 'sha1'|'sha256' $hash
     */
    #[DataProvider('casesProvider')]
    public function test_phpseclib_encrypt_is_unwrapped_by_us(KeyTransportAlgorithm $algorithm, string $hash, int $size): void
    {
        $sessionKey = random_bytes($size);

        $wrapped = $this->phpseclibPublic->withPadding(RSA::ENCRYPTION_OAEP)->withHash($hash)->withMGFHash($hash)->encrypt($sessionKey);
        static::assertIsString($wrapped);

        static::assertSame($sessionKey, (new KeyTransport())->unwrap($wrapped, $this->key, $algorithm));
    }
}
