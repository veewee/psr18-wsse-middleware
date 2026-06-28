<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Internal;

use OpenSSLAsymmetricKey;
use Psl\Ref;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;

/**
 * EME-OAEP encode/decode (PKCS#1 v2.2) with the OAEP hash and MGF1 hash parameterized, paired with raw RSA so
 * the OAEP digest is not pinned to the SHA-1 the high-level openssl API hard-wires. The label L is always the
 * empty string, as XML-Enc has no use for it.
 *
 * Decode accumulates a single validity flag with no early return and no distinct error per cause, so a wrong
 * key, a non-zero leading octet, a wrong label hash and a missing separator are indistinguishable; every
 * failure surfaces as the same OpenSslException, which the caller collapses into its uniform decryption error.
 *
 * @internal
 */
final class Oaep
{
    /**
     * @param 'sha1'|'sha256' $hashAlgorithm
     *
     * @throws OpenSslException when the message is too long for the key or the raw RSA op fails
     */
    public static function encode(
        #[SensitiveParameter] string $message,
        OpenSSLAsymmetricKey $publicKey,
        string $hashAlgorithm,
    ): string {
        $hLen = self::hashLength($hashAlgorithm);
        $k = self::modulusBytes($publicKey);

        $maxMessage = $k - 2 * $hLen - 2;
        if ($maxMessage < 0 || strlen($message) > $maxMessage) {
            // Our own session key on the encrypt side: a non-oracle path, so the real reason may surface.
            throw OpenSslException::operationFailed('OAEP-encode the session key', 'the message is too long for this key');
        }

        $lHash = hash($hashAlgorithm, '', true);
        $ps = str_repeat("\x00", $k - strlen($message) - 2 * $hLen - 2);
        $db = $lHash.$ps."\x01".$message;

        $seed = random_bytes($hLen);
        $dbMask = self::mgf1($seed, $k - $hLen - 1, $hashAlgorithm);
        $maskedDb = $db ^ $dbMask;
        $seedMask = self::mgf1($maskedDb, $hLen, $hashAlgorithm);
        $maskedSeed = $seed ^ $seedMask;

        $em = "\x00".$maskedSeed.$maskedDb;

        return OpenSslCall::output(
            static fn (Ref $cipher): bool => openssl_public_encrypt($em, $cipher->value, $publicKey, OPENSSL_NO_PADDING),
            'OAEP-encrypt the session key',
        );
    }

    /**
     * @param 'sha1'|'sha256' $hashAlgorithm
     *
     * @throws OpenSslException uniformly on any decode failure
     */
    public static function decode(
        #[SensitiveParameter] string $cipher,
        OpenSSLAsymmetricKey $privateKey,
        string $hashAlgorithm,
    ): string {
        $hLen = self::hashLength($hashAlgorithm);
        $k = self::modulusBytes($privateKey);

        $em = OpenSslCall::output(
            static fn (Ref $plain): bool => openssl_private_decrypt($cipher, $plain->value, $privateKey, OPENSSL_NO_PADDING),
            'OAEP-decrypt the session key',
        );

        // The raw RSA integer drops leading zero octets, and EM always begins with 0x00, so the result is
        // routinely shorter than k. Restore the full width before slicing or every offset misaligns.
        $em = str_pad($em, $k, "\x00", STR_PAD_LEFT);

        $lHash = hash($hashAlgorithm, '', true);

        $y = $em[0];
        $maskedSeed = substr($em, 1, $hLen);
        $maskedDb = substr($em, 1 + $hLen);

        $seedMask = self::mgf1($maskedDb, $hLen, $hashAlgorithm);
        $seed = $maskedSeed ^ $seedMask;
        $dbMask = self::mgf1($seed, $k - $hLen - 1, $hashAlgorithm);
        $db = $maskedDb ^ $dbMask;

        $lHashPrime = substr($db, 0, $hLen);

        // Accumulate the verdict in one integer flag, combined bitwise so every check is evaluated and the
        // failing cause is not observable from which branch short-circuited.
        $valid = (int) hash_equals($lHash, $lHashPrime);
        $valid &= (int) ($y === "\x00");

        // Walk the padding string after lHash', requiring all-zero octets up to a single 0x01 separator.
        $separator = -1;
        $sawNonZero = false;
        $length = strlen($db);
        for ($i = $hLen; $i < $length; $i++) {
            $octet = $db[$i];
            if ($octet === "\x01" && $separator === -1 && !$sawNonZero) {
                $separator = $i;
            } elseif ($octet !== "\x00" && $separator === -1) {
                $sawNonZero = true;
            }
        }

        $valid &= (int) !$sawNonZero;
        $valid &= (int) ($separator !== -1);
        if ($valid !== 1) {
            throw OpenSslException::operationFailed('OAEP-decode the session key', '');
        }

        return substr($db, $separator + 1);
    }

    /**
     * @param 'sha1'|'sha256' $hashAlgorithm
     */
    private static function mgf1(string $seed, int $maskLen, string $hashAlgorithm): string
    {
        $hLen = self::hashLength($hashAlgorithm);
        $mask = '';
        for ($i = 0, $blocks = (int) ceil($maskLen / $hLen); $i < $blocks; $i++) {
            $mask .= hash($hashAlgorithm, $seed.pack('N', $i), true);
        }

        return substr($mask, 0, $maskLen);
    }

    /**
     * @param 'sha1'|'sha256' $hashAlgorithm
     *
     * @return int<1, max>
     */
    private static function hashLength(string $hashAlgorithm): int
    {
        return match ($hashAlgorithm) {
            'sha1' => 20,
            'sha256' => 32,
        };
    }

    private static function modulusBytes(OpenSSLAsymmetricKey $key): int
    {
        /** @var array{bits?: int} $details */
        $details = OpenSslCall::run(
            static fn (): array|false => openssl_pkey_get_details($key),
            'read the key modulus length',
        );

        return (int) ceil(($details['bits'] ?? 0) / 8);
    }
}
