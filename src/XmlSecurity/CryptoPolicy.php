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

/**
 * The XML-Security algorithm policy: the outbound algorithm choices and the inbound *accept* allow-lists.
 * Independent of any SOAP concern, so the signing/encryption engine can be driven without the WS-Security
 * profile. Secure-by-default: omitted allow-lists reject sha1 / rsa-1_5 / 3des.
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
    ) {
        $this->acceptedSignatureMethods = self::requireNonEmpty($acceptedSignatureMethods ?? [
            SignatureMethod::RSA_SHA256,
            SignatureMethod::RSA_SHA384,
            SignatureMethod::RSA_SHA512,
            SignatureMethod::ECDSA_SHA256,
            SignatureMethod::ECDSA_SHA384,
            SignatureMethod::ECDSA_SHA512,
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
        $this->acceptedDataEncryptionMethods = self::requireNonEmpty($acceptedDataEncryptionMethods ?? [
            DataEncryptionMethod::AES128_GCM,
            DataEncryptionMethod::AES192_GCM,
            DataEncryptionMethod::AES256_GCM,
            DataEncryptionMethod::AES128_CBC,
            DataEncryptionMethod::AES192_CBC,
            DataEncryptionMethod::AES256_CBC,
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

    /**
     * @return non-empty-list<SignatureMethod>
     */
    public function acceptedSignatureMethods(): array
    {
        return $this->acceptedSignatureMethods;
    }

    /**
     * @return non-empty-list<DigestMethod>
     */
    public function acceptedDigestMethods(): array
    {
        return $this->acceptedDigestMethods;
    }

    /**
     * @return non-empty-list<SignatureCanonicalization>
     */
    public function acceptedCanonicalizations(): array
    {
        return $this->acceptedCanonicalizations;
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
}
