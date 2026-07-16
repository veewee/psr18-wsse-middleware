<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;

/**
 * References a token that already exists in the Security header by its wsu:Id. The result is
 * ds:KeyInfo > wsse:SecurityTokenReference > wsse:Reference URI="#<tokenId>".
 *
 * Pure: it neither embeds the token nor mints the id. The caller embeds the token and mints its id, then
 * constructs this strategy with that id; here it only emits the reference.
 */
final class DirectReferenceKeyIdentifier implements KeyIdentifierInterface
{
    /** @var non-empty-string */
    private string $tokenId;

    /** @var non-empty-string */
    private string $valueType;

    /**
     * @param non-empty-string $tokenId the wsu:Id of the already-embedded token, without the '#'
     * @param non-empty-string $valueType the referenced token's WS-Security ValueType URI
     */
    public function __construct(string $tokenId, string $valueType)
    {
        $this->tokenId = $tokenId;
        $this->valueType = $valueType;
    }

    public function apply(Document $document, Certificate $certificate): Element
    {
        return SecurityTokenReference::reference($this->tokenId, $this->valueType)->buildKeyInfo($document);
    }
}
