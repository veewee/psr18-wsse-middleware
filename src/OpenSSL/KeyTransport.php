<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use Psl\Ref;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\KeyHandleResolver;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\Oaep;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\OaepHash;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;

/**
 * RSA key transport: wrap/unwrap a symmetric session key under a recipient's RSA key. OAEP (the secure
 * default) and the opt-in legacy RSA-1_5 are supported. Unwrap collapses every failure to one uniform error
 * so it cannot become a Bleichenbacher padding oracle.
 *
 * OAEP-SHA-1 rides the high-level openssl padding, which is hard-wired to SHA-1 / MGF1-SHA1. OAEP-SHA-256 has
 * no high-level openssl knob, so it runs the EME-OAEP encode/decode by hand over raw RSA.
 */
final class KeyTransport
{
    public function wrap(
        #[SensitiveParameter] string $sessionKey,
        Certificate $recipientCertificate,
        KeyTransportAlgorithm $algorithm,
    ): string {
        $key = KeyHandleResolver::publicKey($recipientCertificate);

        $handRolledHash = $this->handRolledOaepHash($algorithm);
        if ($handRolledHash !== null) {
            // A failure here is a non-oracle path (our recipient key / data), so the real reason may surface.
            return Oaep::encode($sessionKey, $key, $handRolledHash->value);
        }

        $padding = $this->padding($algorithm->method);

        // A failure here is a non-oracle path (our recipient key / data), so the real reason may surface.
        return OpenSslCall::output(
            static fn (Ref $wrapped): bool => openssl_public_encrypt($sessionKey, $wrapped->value, $key, $padding),
            'wrap the session key',
        );
    }

    public function unwrap(
        #[SensitiveParameter] string $wrappedKey,
        #[SensitiveParameter] Key $privateKey,
        KeyTransportAlgorithm $algorithm,
    ): string {
        // Resolving our own private key is a non-oracle path (config, not the wrapped bytes), so a malformed
        // key surfaces its real reason; only the decrypt below collapses to a uniform error.
        $key = KeyHandleResolver::privateKey($privateKey);

        try {
            $handRolledHash = $this->handRolledOaepHash($algorithm);
            if ($handRolledHash !== null) {
                return Oaep::decode($wrappedKey, $key, $handRolledHash->value);
            }

            $padding = $this->padding($algorithm->method);

            return OpenSslCall::output(
                static fn (Ref $sessionKey): bool => openssl_private_decrypt($wrappedKey, $sessionKey->value, $key, $padding),
            );
        } catch (OpenSslException) {
            // Uniform: never reveal whether RSA padding was valid (Bleichenbacher / Marvin).
            throw CryptoOperationFailed::decryptionFailed();
        }
    }

    /**
     * The OAEP hash that must run the hand-rolled EME-OAEP path, or null when the high-level openssl padding
     * applies (SHA-1 OAEP, both OAEP URIs) or when this is not OAEP at all (RSA-1_5).
     */
    private function handRolledOaepHash(KeyTransportAlgorithm $algorithm): ?OaepHash
    {
        if (!$algorithm->isOaep() || $algorithm->oaepHash === OaepHash::Sha1) {
            return null;
        }

        return $algorithm->oaepHash;
    }

    private function padding(KeyEncryptionMethod $method): int
    {
        return match ($method) {
            // The high-level OAEP padding is SHA-1 / MGF1-SHA1; both OAEP URIs use it for the SHA-1 case.
            KeyEncryptionMethod::RSA_OAEP_MGF1P, KeyEncryptionMethod::RSA_OAEP => OPENSSL_PKCS1_OAEP_PADDING,
            KeyEncryptionMethod::RSA_1_5 => OPENSSL_PKCS1_PADDING,
        };
    }
}
