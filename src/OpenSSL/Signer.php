<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use Psl\Ref;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\UnsupportedAlgorithmException;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\KeyHandleResolver;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;

/**
 * Asymmetric signing and verification (RSA / DSA / ECDSA). One shape covers every asymmetric method because
 * openssl_sign is polymorphic over the key type. HMAC lives outside this primitive (shared-secret input).
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
        return OpenSslCall::output(
            static fn (Ref $signature): bool => openssl_sign($data, $signature->value, $key, $algorithm),
            'sign the data',
        );
    }

    public function verify(
        Certificate $publicCertificate,
        string $data,
        string $signature,
        SignatureMethod $method,
    ): bool {
        $algorithm = $this->algorithm($method);
        $key = KeyHandleResolver::publicKey($publicCertificate);

        // openssl_verify returns 1 (valid), 0 (invalid) or -1 (processing error, e.g. a malformed signature).
        // Only an explicit 1 is "valid": a malformed/garbage signature is never truthy (the xmlseclibs
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
            SignatureMethod::RSA_SHA256 => OPENSSL_ALGO_SHA256,
            SignatureMethod::RSA_SHA384 => OPENSSL_ALGO_SHA384,
            SignatureMethod::RSA_SHA512 => OPENSSL_ALGO_SHA512,
            SignatureMethod::HMAC_SHA1, SignatureMethod::HMAC_SHA256
                => throw UnsupportedAlgorithmException::forAlgorithm($method->value),
        };
    }
}
