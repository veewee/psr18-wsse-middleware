<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Throwable;

/**
 * RSA key transport: wrap/unwrap a symmetric session key under a recipient's RSA key. OAEP (the secure
 * default, with either SHA-1 or SHA-256) and the opt-in legacy RSA-1_5 are supported. Unwrap collapses every
 * failure to one uniform error so it cannot become a padding oracle.
 *
 * Both paddings run through the same vetted RSA implementation so the OAEP digest is not pinned to a single
 * hash and no padding is hand-rolled.
 */
final class KeyTransport
{
    public function wrap(
        #[SensitiveParameter] string $sessionKey,
        Certificate $recipientCertificate,
        KeyTransportAlgorithm $algorithm,
    ): string {
        $publicKey = PublicKeyLoader::load($recipientCertificate->contents());
        if (!$publicKey instanceof PublicKey) {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        $configured = $this->configure($publicKey, $algorithm);
        if (!$configured instanceof PublicKey) {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        // A failure here is a non-oracle path (our recipient key / data), so the real reason may surface.
        $wrapped = $configured->encrypt($sessionKey);
        if (!is_string($wrapped)) {
            throw CryptoOperationFailed::encryptionFailed();
        }

        return $wrapped;
    }

    public function unwrap(
        #[SensitiveParameter] string $wrappedKey,
        #[SensitiveParameter] Key $privateKey,
        KeyTransportAlgorithm $algorithm,
    ): string {
        try {
            $key = PublicKeyLoader::load($privateKey->contents(), $privateKey->passphrase());

            $configured = $key instanceof PrivateKey ? $this->configure($key, $algorithm) : null;
            if (!$configured instanceof PrivateKey) {
                throw CryptoOperationFailed::decryptionFailed();
            }

            $sessionKey = $configured->decrypt($wrappedKey);
            if (!is_string($sessionKey)) {
                throw CryptoOperationFailed::decryptionFailed();
            }

            return $sessionKey;
        } catch (Throwable) {
            // Uniform: never reveal whether RSA padding was valid (Bleichenbacher / Marvin).
            throw CryptoOperationFailed::decryptionFailed();
        }
    }

    private function configure(RSA $key, KeyTransportAlgorithm $algorithm): RSA
    {
        $oaepHash = $algorithm->oaepHash;
        if (!$algorithm->isOaep() || $oaepHash === null) {
            /** @var RSA $configured */
            $configured = $key->withPadding(RSA::ENCRYPTION_PKCS1);

            return $configured;
        }

        /** @var RSA $configured */
        $configured = $key->withPadding(RSA::ENCRYPTION_OAEP);
        /** @var RSA $configured */
        $configured = $configured->withHash($oaepHash->value);
        /** @var RSA $configured */
        $configured = $configured->withMGFHash($oaepHash->value);

        return $configured;
    }
}
