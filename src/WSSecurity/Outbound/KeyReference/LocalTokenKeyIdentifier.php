<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;

/**
 * References a token this same Security header carries, by its wsu:Id: ds:KeyInfo >
 * wsse:SecurityTokenReference > wsse:Reference URI="#...". Used for a local xenc:EncryptedKey and for a local
 * wsc:DerivedKeyToken, neither of which the token profile gives a ValueType.
 *
 * Distinct from DirectReferenceKeyIdentifier, which names a wsse:BinarySecurityToken and repeats that token's
 * ValueType so a receiver can see the two agree.
 */
final readonly class LocalTokenKeyIdentifier implements KeyIdentifierInterface
{
    /**
     * @param non-empty-string $wsuId the referenced element's wsu:Id, without the '#'
     */
    public function __construct(
        private string $wsuId,
    ) {
    }

    public function apply(Document $document): Element
    {
        return SecurityTokenReference::localReference($this->wsuId)->buildKeyInfo($document);
    }
}
