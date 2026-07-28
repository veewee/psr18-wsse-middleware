<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Algorithm;

/**
 * The key-transport choice passed across the wrap/unwrap seam: the algorithm URI paired with the two hashes
 * OAEP takes. Both are null for rsa-1_5, which has no OAEP parameterization.
 *
 * OAEP hashes the label and separately seeds the MGF1 mask, and the two need not agree. The xenc11 rsa-oaep URI
 * declares each, while the legacy rsa-oaep-mgf1p URI fixes the mask to MGF1-SHA1 and leaves only the label hash
 * declarable -- a peer that asks for mgf1p with a SHA-256 label digest is asking for something this pair can
 * express and a single hash cannot.
 *
 * @psalm-immutable
 */
final readonly class KeyTransportAlgorithm
{
    private function __construct(
        public KeyEncryptionMethod $method,
        public ?OaepHash $labelHash,
        public ?OaepHash $mgfHash,
    ) {
    }

    public static function oaepSha1(): self
    {
        return new self(KeyEncryptionMethod::RSA_OAEP, OaepHash::Sha1, OaepHash::Sha1);
    }

    public static function oaepSha256(): self
    {
        return new self(KeyEncryptionMethod::RSA_OAEP, OaepHash::Sha256, OaepHash::Sha256);
    }

    public static function legacyMgf1p(): self
    {
        return new self(KeyEncryptionMethod::RSA_OAEP_MGF1P, OaepHash::Sha1, OaepHash::Sha1);
    }

    public static function rsa1_5(): self
    {
        return new self(KeyEncryptionMethod::RSA_1_5, null, null);
    }

    /**
     * Builds the transport from a key-encryption method paired with the label hash. RSA-1_5 takes neither hash.
     * Under the legacy mgf1p URI the mask is fixed to MGF1-SHA1 whatever the label hash is; under rsa-oaep the
     * two are kept equal, since accepting a mismatched pair would only widen what a peer can ask for. This is
     * the single construction point, so a pairing the URI does not allow cannot be expressed.
     */
    public static function fromMethod(KeyEncryptionMethod $method, OaepHash $labelHash): self
    {
        return match ($method) {
            KeyEncryptionMethod::RSA_1_5 => self::rsa1_5(),
            KeyEncryptionMethod::RSA_OAEP_MGF1P => new self($method, $labelHash, OaepHash::Sha1),
            KeyEncryptionMethod::RSA_OAEP => new self($method, $labelHash, $labelHash),
        };
    }

    public function isOaep(): bool
    {
        return $this->method !== KeyEncryptionMethod::RSA_1_5;
    }
}
