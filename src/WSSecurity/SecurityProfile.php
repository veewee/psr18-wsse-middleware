<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;

/**
 * Optional shared settings value object. Holds the outbound algorithm choices, the timestamp window, and the
 * inbound *accept* allow-lists. Secure-by-default: omitted allow-lists reject sha1 / rsa-1_5 / 3des.
 *
 * @psalm-immutable
 */
final class SecurityProfile
{
    /** @var list<SignatureMethod> */
    private readonly array $acceptedSignatureMethods;
    /** @var list<DigestMethod> */
    private readonly array $acceptedDigestMethods;
    /** @var list<KeyEncryptionMethod> */
    private readonly array $acceptedKeyEncryptionMethods;
    /** @var list<DataEncryptionMethod> */
    private readonly array $acceptedDataEncryptionMethods;

    /**
     * @param list<SignatureMethod>|null      $acceptedSignatureMethods
     * @param list<DigestMethod>|null         $acceptedDigestMethods
     * @param list<KeyEncryptionMethod>|null  $acceptedKeyEncryptionMethods
     * @param list<DataEncryptionMethod>|null $acceptedDataEncryptionMethods
     */
    public function __construct(
        private readonly int $timestampTtl = 300,
        private readonly int $clockSkew = 60,
        private readonly SignatureMethod $signatureMethod = SignatureMethod::RSA_SHA256,
        private readonly DigestMethod $digestMethod = DigestMethod::SHA256,
        private readonly SignatureCanonicalization $canonicalization = SignatureCanonicalization::EXC_C14N,
        private readonly DataEncryptionMethod $dataEncryptionMethod = DataEncryptionMethod::AES256_GCM,
        private readonly KeyEncryptionMethod $keyEncryptionMethod = KeyEncryptionMethod::RSA_OAEP,
        ?array $acceptedSignatureMethods = null,
        ?array $acceptedDigestMethods = null,
        ?array $acceptedKeyEncryptionMethods = null,
        ?array $acceptedDataEncryptionMethods = null,
    ) {
        $this->acceptedSignatureMethods = $acceptedSignatureMethods ?? [
            SignatureMethod::RSA_SHA256,
            SignatureMethod::RSA_SHA384,
            SignatureMethod::RSA_SHA512,
            SignatureMethod::ECDSA_SHA256,
            SignatureMethod::ECDSA_SHA384,
            SignatureMethod::ECDSA_SHA512,
        ];
        $this->acceptedDigestMethods = $acceptedDigestMethods ?? [
            DigestMethod::SHA256,
            DigestMethod::SHA384,
            DigestMethod::SHA512,
        ];
        $this->acceptedKeyEncryptionMethods = $acceptedKeyEncryptionMethods ?? [
            KeyEncryptionMethod::RSA_OAEP,
            KeyEncryptionMethod::RSA_OAEP_MGF1P,
        ];
        $this->acceptedDataEncryptionMethods = $acceptedDataEncryptionMethods ?? [
            DataEncryptionMethod::AES128_GCM,
            DataEncryptionMethod::AES192_GCM,
            DataEncryptionMethod::AES256_GCM,
            DataEncryptionMethod::AES128_CBC,
            DataEncryptionMethod::AES192_CBC,
            DataEncryptionMethod::AES256_CBC,
        ];
    }

    public static function default(): self
    {
        return new self();
    }

    public function timestampTtl(): int
    {
        return $this->timestampTtl;
    }

    public function clockSkew(): int
    {
        return $this->clockSkew;
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
}
