<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use Psl\Ref;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\EcdsaSignature;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\KeyHandleResolver;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;

/**
 * Asymmetric signing and verification (RSA / DSA / ECDSA). One shape covers every asymmetric method because
 * openssl_sign is polymorphic over the key type.
 */
final class Signer
{
    public function sign(
        #[SensitiveParameter] Key $privateKey,
        string $data,
        SignatureMethod $method,
    ): string {
        $algorithm = $this->algorithm($method);
        $key = KeyHandleResolver::privateKey($privateKey);

        // A failure throws OpenSslException with the real reason (a non-oracle path: the private key is
        // ours, not attacker input).
        $signature = OpenSslCall::output(
            static fn (Ref $signature): bool => openssl_sign($data, $signature->value, $key, $algorithm),
            'sign the data',
        );

        // OpenSSL emits ECDSA as DER, but XML Signature carries the fixed-width r||s pair, so convert using
        // the coordinate width read from this key.
        if ($method->isEcdsa()) {
            return EcdsaSignature::derToP1363($signature, $this->coordinateBytes($key));
        }

        return $signature;
    }

    public function verify(
        Certificate $publicCertificate,
        string $data,
        string $signature,
        SignatureMethod $method,
    ): bool {
        $algorithm = $this->algorithm($method);
        $key = KeyHandleResolver::publicKey($publicCertificate);

        // The inbound ECDSA SignatureValue is the fixed-width r||s pair; convert it to the DER that
        // openssl_verify expects. A malformed pair is a normal verification failure, never an error.
        if ($method->isEcdsa()) {
            try {
                $signature = EcdsaSignature::p1363ToDer($signature);
            } catch (InvalidArgumentException) {
                return false;
            }
        }

        // openssl_verify returns 1 (valid), 0 (invalid) or -1 (processing error, e.g. a malformed signature).
        // Only an explicit 1 is "valid": a malformed/garbage signature is never truthy (guarding the
        // "-1 casts to true" trap), and malformed vs merely-invalid are indistinguishable to the caller (no
        // oracle on attacker-controlled signature bytes). A genuine setup error (openssl_verify returns
        // false: bad key/algorithm) surfaces as OpenSslException rather than being silently swallowed.
        return OpenSslCall::run(
            static fn (): int|false => openssl_verify($data, $signature, $key, $algorithm),
            'verify the signature',
        ) === 1;
    }

    private function algorithm(SignatureMethod $method): int
    {
        return match ($method) {
            SignatureMethod::RSA_SHA1, SignatureMethod::DSA_SHA1 => OPENSSL_ALGO_SHA1,
            SignatureMethod::RSA_SHA256, SignatureMethod::ECDSA_SHA256 => OPENSSL_ALGO_SHA256,
            SignatureMethod::RSA_SHA384, SignatureMethod::ECDSA_SHA384 => OPENSSL_ALGO_SHA384,
            SignatureMethod::RSA_SHA512, SignatureMethod::ECDSA_SHA512 => OPENSSL_ALGO_SHA512,
        };
    }

    /**
     * The fixed-width r||s encoding pads each coordinate to the curve's byte length, which follows from the
     * key's bit size (P-256 to 32, P-384 to 48, P-521 to 66).
     */
    private function coordinateBytes(OpenSSLAsymmetricKey $key): int
    {
        $details = OpenSslCall::run(
            static fn (): array|false => openssl_pkey_get_details($key),
            'read the EC key details',
        );
        $bits = (int) ($details['bits'] ?? 0);

        return (int) ceil($bits / 8);
    }
}
