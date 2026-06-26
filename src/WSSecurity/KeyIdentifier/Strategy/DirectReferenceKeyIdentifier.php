<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy;

use Dom\Element;
use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;

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
     * @param string $tokenId the wsu:Id of the already-embedded token, without the '#'
     * @param string $valueType the referenced token's WS-Security ValueType URI
     */
    public function __construct(string $tokenId, string $valueType)
    {
        if ($tokenId === '') {
            throw new InvalidArgumentException('A direct reference requires a non-empty token id.');
        }

        if ($valueType === '') {
            throw new InvalidArgumentException('A direct reference requires a non-empty value type.');
        }

        $this->tokenId = $tokenId;
        $this->valueType = $valueType;
    }

    public function apply(Document $document, Certificate $certificate): Element
    {
        $reference = SecurityTokenReference::reference($this->tokenId, $this->valueType)->build($document);

        return $document->map(namespaced_element(
            WsseNamespace::Ds->value,
            WsseNamespace::Ds->qualify('KeyInfo'),
            children(static fn (): Element => $reference),
        ));
    }
}
