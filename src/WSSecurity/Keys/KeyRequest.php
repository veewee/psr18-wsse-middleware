<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Keys;

/**
 * What a block needs of a symmetric key: how many bytes, and whether that length is a requirement or a
 * preference. The consuming block states it, because the algorithm the block runs is what defines the length;
 * a source restating it would be the same fact written twice, with two places for it to drift.
 *
 * A cipher's length is mandatory: a key of any other size is one it cannot use. A MAC's is preferred, because
 * HMAC pads a short key and hashes a long one, so any length works and the stated one is where the MAC carries
 * its full strength.
 *
 * @psalm-immutable
 */
final readonly class KeyRequest
{
    /**
     * @param positive-int $bytes
     */
    public function __construct(
        public int $bytes,
        public bool $mandatory,
    ) {
    }

    /**
     * @param positive-int $bytes
     */
    public static function exactly(int $bytes): self
    {
        return new self($bytes, mandatory: true);
    }

    /**
     * @param positive-int $bytes
     */
    public static function preferably(int $bytes): self
    {
        return new self($bytes, mandatory: false);
    }
}
