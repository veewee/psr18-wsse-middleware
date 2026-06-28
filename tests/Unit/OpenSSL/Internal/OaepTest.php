<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Internal;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\Oaep;

final class OaepTest extends TestCase
{
    public function test_it_round_trips_with_sha1(): void
    {
        [$public, $private] = $this->keyPair();
        $message = random_bytes(32);

        $encoded = Oaep::encode($message, $public, 'sha1');
        $decoded = Oaep::decode($encoded, $private, 'sha1');

        static::assertSame($message, $decoded);
    }

    public function test_it_round_trips_with_sha256(): void
    {
        [$public, $private] = $this->keyPair();
        $message = random_bytes(32);

        $encoded = Oaep::encode($message, $public, 'sha256');
        $decoded = Oaep::decode($encoded, $private, 'sha256');

        static::assertSame($message, $decoded);
    }

    public function test_our_sha1_decode_reads_a_blob_produced_by_native_openssl_oaep(): void
    {
        [$public, $private] = $this->keyPair();
        $message = random_bytes(32);

        // Encrypt with the high-level openssl OAEP (SHA-1 / MGF1-SHA1), decode with our hand-rolled path.
        static::assertTrue(openssl_public_encrypt($message, $blob, $public, OPENSSL_PKCS1_OAEP_PADDING));
        static::assertIsString($blob);

        static::assertSame($message, Oaep::decode($blob, $private, 'sha1'));
    }

    public function test_native_openssl_decode_reads_a_blob_produced_by_our_sha1_encode(): void
    {
        [$public, $private] = $this->keyPair();
        $message = random_bytes(32);

        $blob = Oaep::encode($message, $public, 'sha1');

        static::assertTrue(openssl_private_decrypt($blob, $decrypted, $private, OPENSSL_PKCS1_OAEP_PADDING));
        static::assertSame($message, $decrypted);
    }

    public function test_it_decodes_messages_whose_encrypted_modulus_has_leading_zero_octets(): void
    {
        // EM always begins with 0x00, so the raw RSA integer routinely drops leading bytes; the decode must
        // re-pad to the modulus length. Round-tripping a batch of random keys exercises that path repeatedly.
        for ($i = 0; $i < 12; $i++) {
            [$public, $private] = $this->keyPair();
            $message = random_bytes(32);

            $encoded = Oaep::encode($message, $public, 'sha256');
            static::assertSame($message, Oaep::decode($encoded, $private, 'sha256'));
        }
    }

    public function test_it_rejects_a_message_longer_than_the_oaep_limit(): void
    {
        [$public] = $this->keyPair();
        // k = 256, hLen = 32 -> mLen limit = 256 - 64 - 2 = 190. One octet over must be refused.
        $tooLong = random_bytes(191);

        $this->expectException(OpenSslException::class);
        Oaep::encode($tooLong, $public, 'sha256');
    }

    public function test_a_blob_decoded_under_the_wrong_hash_fails(): void
    {
        [$public, $private] = $this->keyPair();
        $message = random_bytes(32);

        $encoded = Oaep::encode($message, $public, 'sha1');

        $this->expectException(OpenSslException::class);
        Oaep::decode($encoded, $private, 'sha256');
    }

    /**
     * @return array{0: OpenSSLAsymmetricKey, 1: OpenSSLAsymmetricKey}
     */
    private function keyPair(): array
    {
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);

        $details = openssl_pkey_get_details($private);
        static::assertIsArray($details);
        $public = openssl_pkey_get_public($details['key']);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $public);

        return [$public, $private];
    }
}
