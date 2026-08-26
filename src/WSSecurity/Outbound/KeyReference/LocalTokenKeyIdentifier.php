<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;

/**
 * References an element this same Security header carries, by its wsu:Id: ds:KeyInfo >
 * wsse:SecurityTokenReference > wsse:Reference URI="#...". Used for a local wsc:DerivedKeyToken, and for a
 * local xenc:EncryptedKey where a peer wants the element named rather than the key.
 *
 * Distinct from DirectReferenceKeyIdentifier, which names a wsse:BinarySecurityToken and repeats that token's
 * ValueType so a receiver can see the two agree.
 */
final readonly class LocalTokenKeyIdentifier implements KeyIdentifierInterface
{
    /**
     * @param non-empty-string      $wsuId     the referenced element's wsu:Id, without the '#'
     * @param non-empty-string|null $valueType the referenced element's own type URI, where its profile names
     *        one. Pass it whenever there is one: a receiver enforcing the Basic Security Profile classifies a
     *        reference by what it declares and refuses one it cannot classify
     */
    public function __construct(
        private string $wsuId,
        private ?string $valueType = null,
    ) {
    }

    public function apply(Document $document): Element
    {
        return SecurityTokenReference::localReference($this->wsuId, $this->valueType)->buildKeyInfo($document);
    }
}
