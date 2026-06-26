<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use Psl\Ref;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\KeyHandleResolver;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;

/**
 * RSA key transport: wrap/unwrap a symmetric session key under a recipient's RSA key. OAEP (the secure
 * default) and the opt-in legacy RSA-1_5 are supported. Unwrap collapses every failure to one uniform error
 * so it cannot become a Bleichenbacher padding oracle.
 */
final class KeyTransport
{
    public function wrap(
        #[SensitiveParameter] string $sessionKey,
        Certificate $recipientCertificate,
        KeyEncryptionMethod $method,
    ): string {
        $padding = $this->padding($method);
        $key = KeyHandleResolver::publicKey($recipientCertificate);

        // A failure here is a non-oracle path (our recipient key / data), so the real reason may surface.
        return OpenSslCall::output(
            static fn (Ref $wrapped): bool => openssl_public_encrypt($sessionKey, $wrapped->value, $key, $padding),
            'wrap the session key',
        );
    }

    public function unwrap(
        #[SensitiveParameter] string $wrappedKey,
        #[SensitiveParameter] Key $privateKey,
        KeyEncryptionMethod $method,
    ): string {
        $padding = $this->padding($method);
        // Resolving our own private key is a non-oracle path (config, not the wrapped bytes), so a malformed
        // key surfaces its real reason; only the decrypt below collapses to a uniform error.
        $key = KeyHandleResolver::privateKey($privateKey);

        try {
            return OpenSslCall::output(
                static fn (Ref $sessionKey): bool => openssl_private_decrypt($wrappedKey, $sessionKey->value, $key, $padding),
            );
        } catch (OpenSslException) {
            // Uniform: never reveal whether RSA padding was valid (Bleichenbacher / Marvin).
            throw CryptoOperationFailed::decryptionFailed();
        }
    }

    private function padding(KeyEncryptionMethod $method): int
    {
        return match ($method) {
            // Both OAEP URIs map to OAEP-SHA1/MGF1-SHA1, the only OAEP the high-level openssl API offers.
            // Refusing a non-SHA-1 OAEP parameterization needs the xenc DigestMethod, which is a B5 concern.
            KeyEncryptionMethod::RSA_OAEP_MGF1P, KeyEncryptionMethod::RSA_OAEP => OPENSSL_PKCS1_OAEP_PADDING,
            KeyEncryptionMethod::RSA_1_5 => OPENSSL_PKCS1_PADDING,
        };
    }
}
