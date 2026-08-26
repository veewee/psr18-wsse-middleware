<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use InvalidArgumentException;
use Psl\Hash\Hmac\Algorithm;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;

/**
 * The P_SHA1 key-derivation function WS-SecureConversation derives a key with, which is the TLS 1.0 pseudorandom
 * function over SHA-1: A(0) is the seed, A(i) is HMAC-SHA1(secret, A(i-1)), and the output is the concatenation
 * of HMAC-SHA1(secret, A(i) || seed) taken from the requested offset for the requested length.
 *
 * SHA-1 is not a choice here. The specification names this function, both dialects of it derive with SHA-1, and
 * a peer computing anything else would derive a different key: there is no interoperable alternative to select.
 * Its use as a PRF does not depend on collision resistance, which is what SHA-1 lost.
 *
 * It lives beside the other primitives because it produces key material, and every byte of key material in this
 * package is minted inside this boundary where it can be audited in one place.
 */
final class P_SHA1
{
    /**
     * The upper bound on how many bytes one derivation generates, which is Offset + Length rather than either
     * alone: the stream is built up to the end of the slice, so a key sixteen bytes wide taken ten billion bytes
     * in is not a large key, it is an allocation. A conservative ceiling far above any key any algorithm here
     * takes. Both sides of the wire answer to it, whoever chose the numbers.
     */
    public const int MAX_GENERATED = 128;

    /**
     * The offset and the length are plain ints rather than refined ones, because both arrive from a peer's
     * element or a caller's configuration and the check below is what makes them what the names say.
     *
     * @param non-empty-string $seed   the label concatenated with the nonce, as the specification defines it
     * @param int              $offset how far into the generated stream the key starts
     * @param int              $length how many bytes of it the key is
     *
     * @throws InvalidArgumentException when the secret is empty, or the slice asked for is outside the bound
     */
    public function derive(
        #[SensitiveParameter] SessionKey $secret,
        string $seed,
        int $offset,
        int $length,
    ): SessionKey {
        $key = $secret->bytes();
        if ($key === '') {
            // Deriving from nothing produces a stream anyone can reproduce.
            throw new InvalidArgumentException('A derivation secret must not be empty.');
        }

        if ($offset < 0 || $length < 1) {
            // A slice outside the stream returns a shorter one than was asked for, and SessionKey holds
            // whatever it is given, so an unchecked offset mints a key narrower than the caller believes.
            throw new InvalidArgumentException('A derivation offset must not be negative and its length must be at least one byte.');
        }

        if ($offset + $length > self::MAX_GENERATED) {
            throw new InvalidArgumentException(sprintf(
                'A derivation generates at most %d bytes and this one asked for %d.',
                self::MAX_GENERATED,
                $offset + $length,
            ));
        }

        // Psl's Hmac\Algorithm is the typed source of the algorithm identity; the raw finalization comes from
        // native hash_hmac, because a derived key is bytes rather than the hex Psl returns.
        $algorithm = Algorithm::Sha1->value;

        $stream = '';
        $a = $seed;
        while (strlen($stream) < $offset + $length) {
            $a = hash_hmac($algorithm, $a, $key, binary: true);
            $stream .= hash_hmac($algorithm, $a.$seed, $key, binary: true);
        }

        return SessionKey::fromBytes(substr($stream, $offset, $length));
    }
}
