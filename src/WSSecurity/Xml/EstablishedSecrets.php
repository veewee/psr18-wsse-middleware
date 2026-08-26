<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\SameDocumentId;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\OnlyChild;
use VeeWee\Xml\Dom\Document;

/**
 * Resolves what a wsse:SecurityTokenReference names to a secret this exchange established. The one place the
 * inbound symmetric forms are read, so a signature's ds:KeyInfo, an xenc:EncryptedData's ds:KeyInfo and a
 * wsc:DerivedKeyToken's own reference all understand the same vocabulary.
 *
 * Three forms resolve: an EncryptedKeySHA1 wsse:KeyIdentifier, a wsse:Reference to a local xenc:EncryptedKey,
 * and a wsse:Reference to a local wsc:DerivedKeyToken, which is re-derived from whatever it in turn references.
 * Every one of them ends at a key the exchange holds. Nothing reads a key out of the element a reference points
 * at: an element a peer put in the message is not evidence of a key.
 *
 * A reference this cannot resolve returns null, and what that means is the caller's to decide. It is always a
 * refusal, but which uniform failure it collapses into differs between the signature and the decryption path.
 */
final readonly class EstablishedSecrets
{
    public function __construct(
        private ExchangeKeys $keys,
        private DerivedKeyTokenReader $derivedKeys = new DerivedKeyTokenReader(),
    ) {
    }

    /**
     * @param bool $allowDerivation false while resolving a derived key's own reference, which is what keeps a
     *        token chain from recursing. No peer emits chained derivation and permitting it would let a response
     *        nest tokens until the resolver ran out of stack
     */
    public function forReference(
        Document $document,
        Element $securityTokenReference,
        IdLookup $idLookup,
        bool $allowDerivation = true,
    ): ?SessionKey {
        $reference = OnlyChild::named($securityTokenReference, WsseNamespaces::Wsse, 'Reference');
        if ($reference !== null) {
            return $this->forLocalReference($document, $reference, $idLookup, $allowDerivation);
        }

        $keyIdentifier = OnlyChild::named($securityTokenReference, WsseNamespaces::Wsse, 'KeyIdentifier');
        if ($keyIdentifier === null) {
            return null;
        }

        // Resolved by the identifier's own content, whatever ValueType it declares. EncryptedKeySHA1 is the one
        // this package emits for a wrapped key, but a pre-shared key is named by whatever the two sides agreed
        // on, and there is no list of those to check against. Only an identifier the exchange established
        // resolves either way, so an identifier naming a certificate simply misses and falls through to the
        // certificate forms.
        $value = ElementText::trimmed($keyIdentifier);

        return $value === '' ? null : $this->keys->resolve($value);
    }

    private function forLocalReference(
        Document $document,
        Element $reference,
        IdLookup $idLookup,
        bool $allowDerivation,
    ): ?SessionKey {
        $id = SameDocumentId::parse((string) $reference->getAttribute('URI'));
        if ($id === null) {
            return null;
        }

        try {
            $element = $idLookup->lookup($document, $id);
        } catch (IdReferenceException) {
            // A reference naming no element in this message is still resolvable: a correlated response points at
            // the key its request conveyed, and that request's token does not travel back.
            $element = null;
        }

        if ($element !== null && $this->derivedKeys->supports($element)) {
            return $allowDerivation ? $this->derivedKeys->derive($document, $element, $this, $idLookup) : null;
        }

        // Everything else resolves by the identifier alone. The element a reference points at is never read for
        // key material: only a key the exchange established under that identifier can open anything, so an
        // element a peer planted names nothing.
        return $this->keys->resolve('#'.$id);
    }
}
