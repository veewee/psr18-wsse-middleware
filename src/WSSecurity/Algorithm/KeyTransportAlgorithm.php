<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Algorithm;

/**
 * The key-transport choice passed across the wrap/unwrap seam: the algorithm URI paired with the OAEP hash.
 * The hash is meaningful only for the OAEP URIs; for rsa-1_5 it is null because no OAEP parameterization applies.
 *
 * @psalm-immutable
 */
final readonly class KeyTransportAlgorithm
{
    private function __construct(
        public KeyEncryptionMethod $method,
        public ?OaepHash $oaepHash,
    ) {
    }

    public static function oaepSha1(): self
    {
        return new self(KeyEncryptionMethod::RSA_OAEP, OaepHash::Sha1);
    }

    public static function oaepSha256(): self
    {
        return new self(KeyEncryptionMethod::RSA_OAEP, OaepHash::Sha256);
    }

    public static function legacyMgf1p(): self
    {
        return new self(KeyEncryptionMethod::RSA_OAEP_MGF1P, OaepHash::Sha1);
    }

    public static function rsa1_5(): self
    {
        return new self(KeyEncryptionMethod::RSA_1_5, null);
    }

    /**
     * Builds the transport from a key-encryption method paired with an OAEP hash. RSA-1_5 ignores the hash and
     * carries null; the OAEP methods carry the given hash. This is the single construction point so an invalid
     * method/hash pairing cannot be expressed.
     */
    public static function fromMethod(KeyEncryptionMethod $method, OaepHash $oaepHash): self
    {
        return match ($method) {
            KeyEncryptionMethod::RSA_1_5 => self::rsa1_5(),
            KeyEncryptionMethod::RSA_OAEP, KeyEncryptionMethod::RSA_OAEP_MGF1P => new self($method, $oaepHash),
        };
    }

    public function isOaep(): bool
    {
        return $this->method !== KeyEncryptionMethod::RSA_1_5;
    }
}
