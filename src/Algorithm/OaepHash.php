<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Algorithm;

use Soap\Psr18WsseMiddleware\OpenSSL\Exception\UnsupportedAlgorithmException;

/**
 * The hash that parameterizes OAEP key transport: it drives both the OAEP label digest and the MGF1 hash. The
 * case value is the PHP hash() algorithm name so the OpenSSL layer can consume it directly.
 */
enum OaepHash: string
{
    case Sha1 = 'sha1';
    case Sha256 = 'sha256';

    public function digestMethod(): DigestMethod
    {
        return match ($this) {
            self::Sha1 => DigestMethod::SHA1,
            self::Sha256 => DigestMethod::SHA256,
        };
    }

    public function mgfUri(): string
    {
        return match ($this) {
            self::Sha1 => 'http://www.w3.org/2009/xmlenc11#mgf1sha1',
            self::Sha256 => 'http://www.w3.org/2009/xmlenc11#mgf1sha256',
        };
    }

    /**
     * @throws UnsupportedAlgorithmException for a digest with no OAEP hash counterpart
     */
    public static function fromDigest(DigestMethod $digest): self
    {
        return match ($digest) {
            DigestMethod::SHA1 => self::Sha1,
            DigestMethod::SHA256 => self::Sha256,
            default => throw UnsupportedAlgorithmException::forAlgorithm($digest->value),
        };
    }

    public static function default(): self
    {
        return self::Sha1;
    }
}
