<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use Psl\Ref;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;

/**
 * Symmetric bulk encryption (AES-CBC/GCM, 3DES-CBC). GCM authenticates; CBC does not, so CBC integrity must
 * come from the enclosing signature (enforced a layer up). Every decrypt failure collapses to one uniform
 * error so this is never a padding oracle.
 */
final class Cipher
{
    private const int GCM_TAG_LENGTH = 16;

    public function __construct(
        private readonly Random $random = new Random(),
    ) {
    }

    public function encrypt(
        #[SensitiveParameter] string $plaintext,
        #[SensitiveParameter] string $key,
        DataEncryptionMethod $method,
    ): CipherText {
        $cipher = $this->cipher($method);
        $iv = $this->random->bytes($this->ivLength($method));

        if ($method->isGcm()) {
            // openssl_encrypt writes the GCM tag out-param by reference; a Psl\Ref carries it out cleanly.
            /** @var Ref<string> $tag */
            $tag = new Ref('');
            $bytes = OpenSslCall::run(
                static fn (): string|false => openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag->value, '', self::GCM_TAG_LENGTH),
                'encrypt the data',
            );

            return new CipherText($iv, $bytes, $tag->value);
        }

        // For CBC the IV length equals the block size.
        $padded = $this->pad($plaintext, strlen($iv));
        $bytes = OpenSslCall::run(
            static fn (): string|false => openssl_encrypt($padded, $cipher, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv),
            'encrypt the data',
        );

        return new CipherText($iv, $bytes, null);
    }

    public function decrypt(
        CipherText $cipherText,
        #[SensitiveParameter] string $key,
        DataEncryptionMethod $method,
    ): string {
        $cipher = $this->cipher($method);
        $ivLength = $this->ivLength($method);

        if ($method->isGcm()) {
            if ($cipherText->tag === null || strlen($cipherText->tag) !== self::GCM_TAG_LENGTH) {
                // Reject a truncated/missing tag before decrypt (tag-forgery defense).
                throw CryptoOperationFailed::invalidAuthenticationTag();
            }
            if (strlen($cipherText->iv) !== $ivLength) {
                // openssl silently accepts non-96-bit GCM IVs and weakens GHASH; we refuse.
                throw CryptoOperationFailed::decryptionFailed();
            }

            $tag = $cipherText->tag;

            try {
                return OpenSslCall::run(
                    static fn (): string|false => openssl_decrypt($cipherText->bytes, $cipher, $key, OPENSSL_RAW_DATA, $cipherText->iv, $tag),
                );
            } catch (OpenSslException) {
                throw CryptoOperationFailed::decryptionFailed();
            }
        }

        if (strlen($cipherText->iv) !== $ivLength) {
            throw CryptoOperationFailed::decryptionFailed();
        }

        try {
            $padded = OpenSslCall::run(
                static fn (): string|false => openssl_decrypt($cipherText->bytes, $cipher, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $cipherText->iv),
            );
        } catch (OpenSslException) {
            throw CryptoOperationFailed::decryptionFailed();
        }

        // For CBC the IV length equals the block size.
        return $this->unpad($padded, $ivLength);
    }

    /**
     * ISO 10126 / XML-Enc padding: random filler then a final octet holding the pad length (always 1..block).
     */
    private function pad(string $data, int $blockSize): string
    {
        $padLength = $blockSize - (strlen($data) % $blockSize);
        $filler = $padLength > 1 ? $this->random->bytes($padLength - 1) : '';

        return $data.$filler.chr($padLength);
    }

    private function unpad(string $data, int $blockSize): string
    {
        $length = strlen($data);
        if ($length === 0) {
            throw CryptoOperationFailed::decryptionFailed();
        }

        $padLength = ord($data[$length - 1]);
        // xmlseclibs trusts this byte blindly; we validate it is a plausible pad length.
        if ($padLength < 1 || $padLength > $blockSize || $padLength > $length) {
            throw CryptoOperationFailed::decryptionFailed();
        }

        return substr($data, 0, $length - $padLength);
    }

    /**
     * @return non-empty-string
     */
    private function cipher(DataEncryptionMethod $method): string
    {
        return match ($method) {
            DataEncryptionMethod::TRIPLEDES_CBC => 'des-ede3-cbc',
            DataEncryptionMethod::AES128_CBC => 'aes-128-cbc',
            DataEncryptionMethod::AES192_CBC => 'aes-192-cbc',
            DataEncryptionMethod::AES256_CBC => 'aes-256-cbc',
            DataEncryptionMethod::AES128_GCM => 'aes-128-gcm',
            DataEncryptionMethod::AES192_GCM => 'aes-192-gcm',
            DataEncryptionMethod::AES256_GCM => 'aes-256-gcm',
        };
    }

    /**
     * The IV length per method: 96 bits for GCM, and the block size for CBC (where IV length == block size).
     * Every arm is reachable: GCM uses it to mint/validate the IV; CBC uses it for the IV and the padding.
     *
     * @return positive-int
     */
    private function ivLength(DataEncryptionMethod $method): int
    {
        return match ($method) {
            DataEncryptionMethod::TRIPLEDES_CBC => 8,
            DataEncryptionMethod::AES128_CBC,
            DataEncryptionMethod::AES192_CBC,
            DataEncryptionMethod::AES256_CBC => 16,
            DataEncryptionMethod::AES128_GCM,
            DataEncryptionMethod::AES192_GCM,
            DataEncryptionMethod::AES256_GCM => 12,
        };
    }
}
