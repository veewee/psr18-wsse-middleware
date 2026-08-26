<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\PSHA1;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\DerivedSessionKey;
use Soap\Psr18WsseMiddleware\Xml\ElementName;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\OnlyChild;
use VeeWee\Xml\Dom\Document;

/**
 * Re-derives the key a wsc:DerivedKeyToken describes, from the secret its own reference names.
 *
 * Every derivation parameter is read off the element rather than assumed, because they are the peer's to choose:
 * a token that derived with a different label, at a different offset, or for a different length describes a
 * different key, and deriving with our own defaults would produce one nothing verifies against. Only the
 * function is fixed, because the specification fixes it.
 *
 * Both dialects are read, whichever one the profile emits. A token this cannot read returns null, which is a
 * refusal to whoever asked; nothing here distinguishes one unreadable token from another.
 */
final readonly class DerivedKeyTokenReader
{
    public function __construct(
        private PSHA1 $pSha1 = new PSHA1(),
    ) {
    }

    public function supports(Element $element): bool
    {
        foreach (WsSecureConversationVersion::cases() as $version) {
            if (ElementName::matchesUri($element, $version->value, 'DerivedKeyToken')) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return ?SessionKey null when the token cannot be read, or names a secret this exchange never established
     */
    public function derive(
        Document $document,
        Element $token,
        EstablishedSecrets $secrets,
        IdLookup $idLookup,
    ): ?SessionKey {
        $version = $this->version($token);
        if ($version === null || !$this->derivesWithPSha1($token, $version)) {
            return null;
        }

        $reference = OnlyChild::named($token, WsseNamespaces::Wsse, 'SecurityTokenReference');
        if ($reference === null) {
            return null;
        }

        // Derivation is disallowed one level down: a token derived from a token is a shape no peer emits and a
        // recursion this refuses to follow.
        $deriving = $secrets->forReference($document, $reference, $idLookup, allowDerivation: false);
        if ($deriving === null) {
            return null;
        }

        $offset = $this->offset($token, $version);
        $length = $this->length($token, $version);
        if ($offset === null || $length === null || $offset + $length > PSHA1::MAX_GENERATED) {
            return null;
        }

        $nonce = base64_decode($this->text($token, $version, 'Nonce') ?? '', true);
        if ($nonce === false || $nonce === '') {
            return null;
        }

        $label = $this->text($token, $version, 'Label') ?? DerivedSessionKey::DEFAULT_LABEL;

        return $this->pSha1->derive($deriving, $label.$nonce, $offset, $length);
    }

    /**
     * Whether the token derives with the one function this reads.
     *
     * The attribute is optional and the specification's default is P_SHA1, which is why an absent one is
     * accepted rather than refused: the reference implementation omits it entirely, so requiring it would leave
     * every token it emits unreadable. A present attribute naming anything else is refused, because a token that
     * derived some other way describes a key this cannot reproduce.
     */
    private function derivesWithPSha1(Element $token, WsSecureConversationVersion $version): bool
    {
        $declared = (string) $token->getAttribute('Algorithm');

        return $declared === '' || $declared === $version->derivationAlgorithm();
    }

    private function version(Element $token): ?WsSecureConversationVersion
    {
        foreach (WsSecureConversationVersion::cases() as $version) {
            if (ElementName::matchesUri($token, $version->value, 'DerivedKeyToken')) {
                return $version;
            }
        }

        return null;
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
    private function offset(Element $token, WsSecureConversationVersion $version): ?int
    {
        $offset = $this->text($token, $version, 'Offset');
        $generation = $this->text($token, $version, 'Generation');

        if ($offset !== null && $generation !== null) {
            return null;
        }

        if ($generation !== null) {
            $length = $this->length($token, $version);
            $counted = $this->nonNegativeInt($generation);

            return $length === null || $counted === null ? null : $counted * $length;
        }

        return $offset === null ? 0 : $this->nonNegativeInt($offset);
    }

    /**
     * @return ?positive-int
     */
    private function length(Element $token, WsSecureConversationVersion $version): ?int
    {
        $declared = $this->text($token, $version, 'Length');
        // The default both dialects state when the element is absent.
        $length = $declared === null ? 32 : $this->nonNegativeInt($declared);

        return $length === null || $length < 1 || $length > PSHA1::MAX_GENERATED ? null : $length;
    }

    /**
     * @return ?non-negative-int
     */
    private function nonNegativeInt(string $text): ?int
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
    private function text(Element $token, WsSecureConversationVersion $version, string $localName): ?string
    {
        $child = OnlyChild::named($token, $version, $localName);
        if ($child === null) {
            return null;
        }

        $text = ElementText::trimmed($child);

        return $text === '' ? null : $text;
    }
}
