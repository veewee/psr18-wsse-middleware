<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Keys;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;

/**
 * A materialized symmetric key: the bytes, how a consumer points a ds:KeyInfo at it, and every form an inbound
 * reference may use to name it.
 *
 * One reference, used by every consumer. A ds:Signature and an xenc:EncryptedData keyed by the same key name it
 * the same way, which is what makes them the same key to a reader, and it is what the reference implementation
 * emits: a session key is named by an identifier of its own rather than by the element that happens to carry it.
 *
 * The carrier is the element an xenc:ReferenceList may be nested into, when there is one. A lone encryption
 * nests its list there and needs no ds:KeyInfo on anything, which is the shape every stack has always read; a
 * shared key cannot, because whoever took the key first may already have signed that element.
 *
 * The wire identifiers travel with the key rather than being registered separately, because a key nothing can
 * name inbound is a response nobody can verify. ExchangeKeys establishes them itself when it materializes the
 * key, so no call site can forget to.
 */
final readonly class SymmetricKey
{
    /**
     * @param list<non-empty-string> $wireIdentifiers
     * @param ?Element $referenceListCarrier the element an xenc:ReferenceList may be nested into, which is an
     *        xenc:EncryptedKey and nothing else: it is the one element whose schema takes the list. Null for a
     *        key carried by anything else, or by nothing
     */
    public function __construct(
        public SessionKey $bytes,
        public KeyIdentifier $keyIdentifier,
        public array $wireIdentifiers = [],
        public ?Element $referenceListCarrier = null,
    ) {
    }

    /**
     * @return positive-int
     */
    public function length(): int
    {
        $length = strlen($this->bytes->bytes());

        /** @var positive-int */
        return $length;
    }
}
