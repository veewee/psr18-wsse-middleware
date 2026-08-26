<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Dom\Element;
use Soap\Psr18WsseMiddleware\OpenSSL\PSHA1;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\DerivedSessionKey;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\OnlyChild;

/**
 * The derivation a wsc:DerivedKeyToken declares: which seed, how far in, and how wide.
 *
 * Every value is read off the element rather than assumed, because they are the peer's to choose: a token that
 * derived with a different label, at a different offset, or for a different length describes a different key,
 * and deriving with our own defaults would produce one nothing verifies against.
 *
 * They arrive as text a peer wrote, so this is where every bound on them lives. A token stating something this
 * cannot read is not an error to report but a token to refuse, which is why reading returns null throughout.
 */
final readonly class DerivedKeyParameters
{
    /**
     * @param non-empty-string $seed   the label concatenated with the nonce, which is what P_SHA1 derives from
     * @param non-negative-int $offset
     * @param positive-int     $length
     */
    private function __construct(
        public string $seed,
        public int $offset,
        public int $length,
    ) {
    }

    /**
     * @return ?self null when the token states something unreadable, out of range, or contradictory
     */
    public static function readFrom(Element $token, WsSecureConversationVersion $version): ?self
    {
        $offset = self::offset($token, $version);
        $length = self::length($token, $version);
        if ($offset === null || $length === null || $offset + $length > PSHA1::MAX_GENERATED) {
            return null;
        }

        $nonce = base64_decode(self::text($token, $version, 'Nonce') ?? '', true);
        if ($nonce === false || $nonce === '') {
            return null;
        }

        $label = self::text($token, $version, 'Label') ?? DerivedSessionKey::DEFAULT_LABEL;

        return new self($label.$nonce, $offset, $length);
    }

    /**
     * The position the key starts at, from either spelling the schema allows.
     *
     * wsc:Generation counts in multiples of the length and wsc:Offset counts in bytes, so the two express the
     * same position two ways. A token carrying both describes two positions, and picking one would let a sender
     * decide which a receiver reads.
     *
     * @return ?non-negative-int
     */
    private static function offset(Element $token, WsSecureConversationVersion $version): ?int
    {
        $offset = self::text($token, $version, 'Offset');
        $generation = self::text($token, $version, 'Generation');

        if ($offset !== null && $generation !== null) {
            return null;
        }

        if ($generation !== null) {
            $length = self::length($token, $version);
            $counted = self::nonNegativeInt($generation);

            return $length === null || $counted === null ? null : $counted * $length;
        }

        return $offset === null ? 0 : self::nonNegativeInt($offset);
    }

    /**
     * @return ?positive-int
     */
    private static function length(Element $token, WsSecureConversationVersion $version): ?int
    {
        $declared = self::text($token, $version, 'Length');
        // The default both dialects state when the element is absent.
        $length = $declared === null ? 32 : self::nonNegativeInt($declared);

        return $length === null || $length < 1 || $length > PSHA1::MAX_GENERATED ? null : $length;
    }

    /**
     * @return ?non-negative-int
     */
    private static function nonNegativeInt(string $text): ?int
    {
        if (!preg_match('/^\d{1,10}$/', $text)) {
            return null;
        }

        /** @var non-negative-int */
        return (int) $text;
    }

    /**
     * @return ?non-empty-string
     */
    private static function text(Element $token, WsSecureConversationVersion $version, string $localName): ?string
    {
        $child = OnlyChild::named($token, $version, $localName);
        if ($child === null) {
            return null;
        }

        $text = ElementText::trimmed($child);

        return $text === '' ? null : $text;
    }
}
