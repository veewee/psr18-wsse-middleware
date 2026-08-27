<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\OaepHash;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\PublicKeyFamily;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\PublicKeyStrength;

/**
 * The XML-Security algorithm policy: the outbound algorithm choices and the inbound *accept* allow-lists.
 * Independent of any SOAP concern, so the signing/encryption engine can be driven without the WS-Security
 * profile. Secure-by-default, on one rule: an omitted allow-list accepts the algorithms that are sound on
 * their own and rejects every weak or unauthenticated one (sha1, ripemd160, dsa, rsa-1_5, 3des, AES-CBC), so
 * reaching a peer that offers nothing better is always a deliberate act.
 *
 * @psalm-immutable
 */
final class CryptoPolicy
{
    /** @var non-empty-list<SignatureMethod> */
    private readonly array $acceptedSignatureMethods;
    /** @var non-empty-list<DigestMethod> */
    private readonly array $acceptedDigestMethods;
    /** @var non-empty-list<KeyEncryptionMethod> */
    private readonly array $acceptedKeyEncryptionMethods;
    /** @var non-empty-list<DataEncryptionMethod> */
    private readonly array $acceptedDataEncryptionMethods;
    /** @var non-empty-list<OaepHash> */
    private readonly array $acceptedOaepHashes;
    /** @var non-empty-list<SignatureCanonicalization> */
    private readonly array $acceptedCanonicalizations;

    /**
     * @param list<SignatureMethod>|null           $acceptedSignatureMethods
     * @param list<DigestMethod>|null              $acceptedDigestMethods
     * @param list<KeyEncryptionMethod>|null       $acceptedKeyEncryptionMethods
     * @param list<DataEncryptionMethod>|null      $acceptedDataEncryptionMethods
     * @param list<OaepHash>|null                  $acceptedOaepHashes
     * @param list<SignatureCanonicalization>|null $acceptedCanonicalizations
     */
    public function __construct(
        private readonly SignatureMethod $signatureMethod = SignatureMethod::RSA_SHA256,
        private readonly DigestMethod $digestMethod = DigestMethod::SHA256,
        private readonly SignatureCanonicalization $canonicalization = SignatureCanonicalization::EXC_C14N,
        private readonly DataEncryptionMethod $dataEncryptionMethod = DataEncryptionMethod::AES256_GCM,
        private readonly KeyEncryptionMethod $keyEncryptionMethod = KeyEncryptionMethod::RSA_OAEP,
        private readonly OaepHash $oaepHash = OaepHash::Sha1,
        ?array $acceptedSignatureMethods = null,
        ?array $acceptedDigestMethods = null,
        ?array $acceptedKeyEncryptionMethods = null,
        ?array $acceptedDataEncryptionMethods = null,
        ?array $acceptedOaepHashes = null,
        ?array $acceptedCanonicalizations = null,
        private readonly int $minimumRsaKeyBits = 1024,
        private readonly int $minimumEcKeyBits = 224,
    ) {
        // WS-Security predates the 2048-bit norm and this is a client library: the peer chooses its own key, so
        // the floor admits the sizes legacy services still run and refuses only the sizes that are broken
        // outright. Raise it when your peer allows. Nothing else enforces this, since OpenSSL's path validation
        // carries no key-size policy (its security levels govern TLS handshakes, not certificate chains).
        if ($minimumRsaKeyBits < 1 || $minimumEcKeyBits < 1) {
            throw new InvalidArgumentException('A minimum key size must be a positive number of bits.');
        }

        $this->acceptedSignatureMethods = self::requireNonEmpty($acceptedSignatureMethods ?? [
            SignatureMethod::RSA_SHA256,
            SignatureMethod::RSA_SHA384,
            SignatureMethod::RSA_SHA512,
            SignatureMethod::ECDSA_SHA256,
            SignatureMethod::ECDSA_SHA384,
            SignatureMethod::ECDSA_SHA512,
            // The HMAC methods follow the same rule their RSA counterparts do: the SHA-2 sizes are sound and
            // the SHA-1 one is named deliberately or not at all. Accepting a keyed MAC costs nothing to a
            // deployment that establishes no symmetric secret, because the verifier refuses an HMAC signature
            // whose ds:KeyInfo resolved to a certificate rather than to a secret this exchange established.
            SignatureMethod::HMAC_SHA256,
            SignatureMethod::HMAC_SHA384,
            SignatureMethod::HMAC_SHA512,
        ], 'signature method');
        $this->acceptedDigestMethods = self::requireNonEmpty($acceptedDigestMethods ?? [
            DigestMethod::SHA256,
            DigestMethod::SHA384,
            DigestMethod::SHA512,
        ], 'digest method');
        $this->acceptedKeyEncryptionMethods = self::requireNonEmpty($acceptedKeyEncryptionMethods ?? [
            KeyEncryptionMethod::RSA_OAEP,
            KeyEncryptionMethod::RSA_OAEP_MGF1P,
        ], 'key encryption method');
        // Only the GCM ciphers authenticate their own ciphertext, and nothing here ties a decrypted part to a
        // region a verified signature covered. A CBC part is therefore decrypted on a peer's word alone, and the
        // difference between a returned response and a thrown one tells a caller who can trigger requests
        // whether their crafted ciphertext was accepted, which recovers the plaintext byte by byte. CBC joins
        // sha1, rsa-1_5 and 3des as something a deployment names deliberately rather than inherits.
        $this->acceptedDataEncryptionMethods = self::requireNonEmpty($acceptedDataEncryptionMethods ?? [
            DataEncryptionMethod::AES128_GCM,
            DataEncryptionMethod::AES192_GCM,
            DataEncryptionMethod::AES256_GCM,
        ], 'data encryption method');
        $this->acceptedOaepHashes = self::requireNonEmpty($acceptedOaepHashes ?? [
            OaepHash::Sha1,
            OaepHash::Sha256,
        ], 'OAEP hash');
        // Both exclusive variants are accepted by default. The inclusive variants are not the WSSE norm, so
        // accepting them would only widen the attack surface; inclusive canonicalization is opt-in by passing
        // it here.
        $this->acceptedCanonicalizations = self::requireNonEmpty($acceptedCanonicalizations ?? [
            SignatureCanonicalization::EXC_C14N,
            SignatureCanonicalization::EXC_C14N_COMMENTS,
        ], 'canonicalization');
    }

    /**
     * @template T
     *
     * @param list<T> $list
     *
     * @return non-empty-list<T>
     */
    private static function requireNonEmpty(array $list, string $label): array
    {
        if ($list === []) {
            throw new InvalidArgumentException(sprintf('The %s allow-list must not be empty.', $label));
        }

        return $list;
    }

    public static function default(): self
    {
        return new self();
    }

    public function signatureMethod(): SignatureMethod
    {
        return $this->signatureMethod;
    }

    public function digestMethod(): DigestMethod
    {
        return $this->digestMethod;
    }

    public function canonicalization(): SignatureCanonicalization
    {
        return $this->canonicalization;
    }

    public function dataEncryptionMethod(): DataEncryptionMethod
    {
        return $this->dataEncryptionMethod;
    }

    public function keyEncryptionMethod(): KeyEncryptionMethod
    {
        return $this->keyEncryptionMethod;
    }

    public function oaepHash(): OaepHash
    {
        return $this->oaepHash;
    }

    public function acceptsSignatureMethod(SignatureMethod $method): bool
    {
        return in_array($method, $this->acceptedSignatureMethods, true);
    }

    public function acceptsDigestMethod(DigestMethod $method): bool
    {
        return in_array($method, $this->acceptedDigestMethods, true);
    }

    public function acceptsKeyEncryptionMethod(KeyEncryptionMethod $method): bool
    {
        return in_array($method, $this->acceptedKeyEncryptionMethods, true);
    }

    public function acceptsDataEncryptionMethod(DataEncryptionMethod $method): bool
    {
        return in_array($method, $this->acceptedDataEncryptionMethods, true);
    }

    public function acceptsOaepHash(OaepHash $hash): bool
    {
        return in_array($hash, $this->acceptedOaepHashes, true);
    }

    public function acceptsCanonicalization(SignatureCanonicalization $canonicalization): bool
    {
        return in_array($canonicalization, $this->acceptedCanonicalizations, true);
    }

    public function acceptsRsaKeyBits(int $bits): bool
    {
        return $bits >= $this->minimumRsaKeyBits;
    }

    public function acceptsEcKeyBits(int $bits): bool
    {
        return $bits >= $this->minimumEcKeyBits;
    }

    /**
     * Whether a signer's key clears the floor for its own family. A key family this library cannot verify with
     * has no floor to clear and is left to the signature check, which refuses it for a reason of its own.
     */
    public function acceptsPublicKeyStrength(PublicKeyStrength $strength): bool
    {
        return match ($strength->family) {
            PublicKeyFamily::Rsa, PublicKeyFamily::Dsa => $this->acceptsRsaKeyBits($strength->bits),
            PublicKeyFamily::Ec => $this->acceptsEcKeyBits($strength->bits),
            // A family this package cannot classify has no floor to be measured against, so there is no size
            // at which it is known to be safe. It is refused rather than admitted: the signature check runs on
            // a different key parser than the one that produced this verdict, so "nothing could verify with it
            // anyway" is not something this decision may assume. Every algorithm the profile accepts resolves
            // to RSA, DSA or EC, so refusing here costs no supported signer.
            PublicKeyFamily::Other => false,
        };
    }
}
