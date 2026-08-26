<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Keys;

use InvalidArgumentException;
use LogicException;

/**
 * What a block needs of a symmetric key: how many bytes, whether that length is a requirement or a preference,
 * and whether the key that answered meets it. The consuming block states it, because the algorithm the block
 * runs is what defines the length; a source restating it would be the same fact written twice, with two places
 * for it to drift.
 *
 * A cipher's length is mandatory: a key of any other size is one it cannot use. A MAC's is preferred, because
 * HMAC pads a short key and hashes a long one, so any length works and the stated one is where the MAC carries
 * its full strength.
 */
final readonly class KeyRequest
{
    /**
     * @param ?positive-int $bytes null when the block has no length to state at all
     */
    public function __construct(
        public ?int $bytes,
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

    /**
     * No length preference at all, for a caller that wants a source's secret registered rather than sized.
     * Distinct from preferring a width nobody actually prefers, which reads as a number that means something.
     */
    public static function any(): self
    {
        return new self(null, mandatory: false);
    }

    /**
     * The width to mint, for a source that has to choose one before there is a key to measure.
     *
     * A request stating no width cannot be minted from, and says so rather than falling back: what a key is
     * for is the block's to state, and a default chosen here would be this class answering it. Reachable only
     * by wiring a minting source where a registration-only one belongs.
     *
     * @return positive-int
     *
     * @throws LogicException
     */
    public function mintingWidth(): int
    {
        if ($this->bytes === null) {
            throw new LogicException('A key cannot be minted for a block that states no width.');
        }

        return $this->bytes;
    }

    /**
     * Refuses a key whose width this request required and did not get.
     *
     * The rule lives here rather than in each source, because it is a property of what was asked rather than of
     * what answered. Both numbers appear, since which of the two is wrong is the caller's to decide. What the
     * key is called and what to do about it stay the source's to phrase, because both differ by where the key
     * came from.
     *
     * @throws InvalidArgumentException
     */
    public function enforce(SymmetricKey $key, string $subject, string $remedy): void
    {
        $required = $this->mandatory ? $this->bytes : null;
        if ($required === null || $key->length() === $required) {
            return;
        }

        // A key of the wrong width fails at the peer with nothing local to explain it, so it is named here.
        throw new InvalidArgumentException(sprintf(
            '%s is %d bytes and this block needs exactly %d. %s',
            $subject,
            $key->length(),
            $required,
            $remedy,
        ));
    }
}
