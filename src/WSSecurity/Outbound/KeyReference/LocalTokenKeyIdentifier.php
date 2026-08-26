<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecureConversationVersion;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;

/**
 * References the wsc:DerivedKeyToken this same Security header carries, by its wsu:Id: ds:KeyInfo >
 * wsse:SecurityTokenReference > wsse:Reference URI="#...".
 *
 * The reference declares the token's own @ValueType, which is dialect-specific. A receiver enforcing the Basic
 * Security Profile classifies a reference by what it declares and refuses one it cannot classify, so a reference
 * declaring nothing is rejected for whatever shape the receiver guessed at.
 *
 * Distinct from DirectReferenceKeyIdentifier, which names a wsse:BinarySecurityToken and repeats that token's
 * ValueType so a receiver can see the two agree.
 */
final readonly class LocalTokenKeyIdentifier implements KeyIdentifierInterface
{
    /**
     * @param non-empty-string $wsuId the token's wsu:Id, without the '#'
     */
    public function __construct(
        private string $wsuId,
        private WsSecureConversationVersion $version,
    ) {
    }

    public function apply(Document $document): Element
    {
        return SecurityTokenReference::localReference($this->wsuId, $this->version->derivedKeyTokenType())
            ->buildKeyInfo($document);
    }
}
