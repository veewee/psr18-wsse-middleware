<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use LogicException;
use Psl\Hash\Hmac\Algorithm;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureKeyKind;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use function Psl\Hash\equals;

/**
 * Keyed message authentication over a symmetric secret, for the HMAC signature methods. Separate from the
 * Signer alongside it because a MAC is not a signature: one key both produces and checks it, so it identifies
 * no party and there is no certificate to load.
 *
 * The comparison is constant-time and refuses unequal lengths, which is what makes a truncated MAC a failure
 * rather than a prefix match.
 */
final class Hmac
{
    /**
     * @return non-empty-string the raw MAC bytes, which is what the XML-DSig SignatureValue carries base64
     *
     * @throws LogicException when the method is not an HMAC one, or the secret is empty
     */
    public function compute(
        string $data,
        #[SensitiveParameter] SessionKey $secret,
        SignatureMethod $method,
    ): string {
        if ($method->keyKind() !== SignatureKeyKind::Hmac) {
            throw new LogicException(sprintf('%s is not an HMAC signature method.', $method->name));
        }

        $key = $secret->bytes();
        if ($key === '') {
            // HMAC accepts a zero-length key and produces a value anyone can reproduce, so an empty secret is
            // a MAC that authenticates nobody rather than a weak one.
            throw new LogicException('An HMAC secret must not be empty.');
        }

        /** @var non-empty-string $computed */
        $computed = hash_hmac($this->algorithm($method)->value, $data, $key, binary: true);

        return $computed;
    }

    /**
     * @throws LogicException when the method is not an HMAC one, or the secret is empty
     */
    public function verify(
        string $data,
        #[SensitiveParameter] SessionKey $secret,
        string $value,
        SignatureMethod $method,
    ): bool {
        return equals($this->compute($data, $secret, $method), $value);
    }

    /**
     * Psl's Hmac\Algorithm is the typed source of the algorithm identity; the raw finalization comes from
     * native hash_hmac, because the XML-DSig SignatureValue carries the raw bytes rather than hex.
     */
    private function algorithm(SignatureMethod $method): Algorithm
    {
        return match ($method) {
            SignatureMethod::HMAC_SHA1 => Algorithm::Sha1,
            SignatureMethod::HMAC_SHA224 => Algorithm::Sha224,
            SignatureMethod::HMAC_SHA256 => Algorithm::Sha256,
            SignatureMethod::HMAC_SHA384 => Algorithm::Sha384,
            SignatureMethod::HMAC_SHA512 => Algorithm::Sha512,
            SignatureMethod::RSA_SHA1,
            SignatureMethod::RSA_SHA256,
            SignatureMethod::RSA_SHA384,
            SignatureMethod::RSA_SHA512,
            SignatureMethod::DSA_SHA1,
            SignatureMethod::ECDSA_SHA256,
            SignatureMethod::ECDSA_SHA384,
            SignatureMethod::ECDSA_SHA512 => throw new LogicException(
                sprintf('%s is not an HMAC signature method.', $method->name),
            ),
        };
    }
}
