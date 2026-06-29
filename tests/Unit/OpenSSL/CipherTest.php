<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\CipherText;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;

final class CipherTest extends TestCase
{
    /**
     * @return array<string, array{0: DataEncryptionMethod, 1: int}>
     */
    public static function methods(): array
    {
        return [
            '3des-cbc' => [DataEncryptionMethod::TRIPLEDES_CBC, 24],
            'aes128-cbc' => [DataEncryptionMethod::AES128_CBC, 16],
            'aes192-cbc' => [DataEncryptionMethod::AES192_CBC, 24],
            'aes256-cbc' => [DataEncryptionMethod::AES256_CBC, 32],
            'aes128-gcm' => [DataEncryptionMethod::AES128_GCM, 16],
            'aes192-gcm' => [DataEncryptionMethod::AES192_GCM, 24],
            'aes256-gcm' => [DataEncryptionMethod::AES256_GCM, 32],
        ];
    }

    #[DataProvider('methods')]
    public function test_it_round_trips_every_method(DataEncryptionMethod $method, int $keySize): void
    {
        $cipher = new Cipher();
        $key = SessionKey::fromBytes(random_bytes($keySize));
        $plaintext = 'the SOAP body to protect';

        $cipherText = $cipher->encrypt($plaintext, $key, $method);

        static::assertSame($plaintext, $cipher->decrypt($cipherText, $key, $method));
    }

    public function test_gcm_uses_a_fresh_96_bit_iv_per_operation(): void
    {
        $cipher = new Cipher();
        $key = SessionKey::fromBytes(random_bytes(32));

        $first = $cipher->encrypt('same', $key, DataEncryptionMethod::AES256_GCM);
        $second = $cipher->encrypt('same', $key, DataEncryptionMethod::AES256_GCM);

        static::assertSame(12, strlen($first->iv));
        static::assertNotSame($first->iv, $second->iv);
        static::assertSame(16, strlen((string) $first->tag));
    }

    public function test_gcm_rejects_a_truncated_authentication_tag_before_decrypt(): void
    {
        $cipher = new Cipher();
        $key = SessionKey::fromBytes(random_bytes(32));
        $cipherText = $cipher->encrypt('secret', $key, DataEncryptionMethod::AES256_GCM);
        $truncated = new CipherText($cipherText->iv, $cipherText->bytes, substr((string) $cipherText->tag, 0, 8));

        $this->expectException(CryptoOperationFailed::class);
        $cipher->decrypt($truncated, $key, DataEncryptionMethod::AES256_GCM);
    }

    public function test_gcm_rejects_a_non_96_bit_iv(): void
    {
        $cipher = new Cipher();
        $key = SessionKey::fromBytes(random_bytes(32));
        $cipherText = $cipher->encrypt('secret', $key, DataEncryptionMethod::AES256_GCM);
        $badIv = new CipherText(substr($cipherText->iv, 0, 8), $cipherText->bytes, $cipherText->tag);

        $this->expectException(CryptoOperationFailed::class);
        $cipher->decrypt($badIv, $key, DataEncryptionMethod::AES256_GCM);
    }

    public function test_gcm_rejects_tampered_ciphertext(): void
    {
        $cipher = new Cipher();
        $key = SessionKey::fromBytes(random_bytes(32));
        $cipherText = $cipher->encrypt('secret', $key, DataEncryptionMethod::AES256_GCM);
        $tampered = new CipherText($cipherText->iv, $cipherText->bytes ^ str_repeat("\x01", strlen($cipherText->bytes)), $cipherText->tag);

        $this->expectException(CryptoOperationFailed::class);
        $cipher->decrypt($tampered, $key, DataEncryptionMethod::AES256_GCM);
    }

    public function test_cbc_rejects_an_invalid_pad_length(): void
    {
        $cipher = new Cipher();
        $key = SessionKey::fromBytes(random_bytes(32));
        $iv = random_bytes(16);
        // Craft plaintext whose last byte is an impossible pad length (0), encrypted with zero padding.
        $raw = str_repeat('A', 15)."\x00";
        $bytes = openssl_encrypt($raw, 'aes-256-cbc', $key->bytes(), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        static::assertIsString($bytes);

        $this->expectException(CryptoOperationFailed::class);
        $cipher->decrypt(new CipherText($iv, $bytes, null), $key, DataEncryptionMethod::AES256_CBC);
    }

    public function test_cbc_failures_are_uniform_regardless_of_cause(): void
    {
        $cipher = new Cipher();
        $key = SessionKey::fromBytes(random_bytes(32));
        $iv = random_bytes(16);

        // Cause A: ciphertext length is not a block multiple (openssl returns false).
        $a = $this->captureFailureMessage($cipher, new CipherText($iv, 'not-a-block', null), $key);
        // Cause B: a clean decrypt that yields an invalid pad length.
        $raw = str_repeat('A', 15)."\xff";
        $bytes = openssl_encrypt($raw, 'aes-256-cbc', $key->bytes(), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        static::assertIsString($bytes);
        $b = $this->captureFailureMessage($cipher, new CipherText($iv, $bytes, null), $key);

        static::assertSame($a, $b);
    }

    private function captureFailureMessage(Cipher $cipher, CipherText $cipherText, SessionKey $key): string
    {
        try {
            $cipher->decrypt($cipherText, $key, DataEncryptionMethod::AES256_CBC);
        } catch (CryptoOperationFailed $exception) {
            return $exception->getMessage();
        }

        static::fail('Expected a CryptoOperationFailed exception.');
    }
}
