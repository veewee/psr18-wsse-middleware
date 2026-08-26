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
     * @param non-empty-string $seed   the label concatenated with the nonce, as the specification defines it
     * @param non-negative-int $offset how far into the generated stream the key starts
     * @param positive-int     $length how many bytes of it the key is
     *
     * @throws InvalidArgumentException when the secret is empty
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
