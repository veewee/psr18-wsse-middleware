<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\PSHA1;
use Soap\Psr18WsseMiddleware\Xml\ElementName;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\OnlyChild;
use VeeWee\Xml\Dom\Document;

/**
 * Re-derives the key a wsc:DerivedKeyToken describes, from the secret its own reference names.
 *
 * What this decides is which dialect the token speaks, that it derives with the one function this reads, and
 * which secret it derives from. What the derivation itself says is DerivedKeyParameters', because those values
 * are the peer's text and every bound on them belongs with the reading of them.
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

        $parameters = DerivedKeyParameters::readFrom($token, $version);

        return $parameters === null
            ? null
            : $this->pSha1->derive($deriving, $parameters->seed, $parameters->offset, $parameters->length);
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
}
