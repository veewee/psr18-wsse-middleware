<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;

/**
 * A generic key-reference escape hatch for profile-specific ValueTypes that the named strategies do not cover.
 * The result is ds:KeyInfo > wsse:SecurityTokenReference > wsse:KeyIdentifier with the caller-supplied value,
 * value type and encoding. Prefer a named strategy where one exists.
 */
final class CustomKeyIdentifier implements KeyIdentifierInterface
{
    /** @var non-empty-string */
    private string $encodedValue;

    /** @var non-empty-string */
    private string $valueType;

    /** @var non-empty-string */
    private string $encodingType;

    /**
     * @param non-empty-string $encodedValue
     * @param non-empty-string $valueType
     * @param non-empty-string $encodingType
     */
    public function __construct(string $encodedValue, string $valueType, string $encodingType)
    {
        $this->encodedValue = $encodedValue;
        $this->valueType = $valueType;
        $this->encodingType = $encodingType;
    }

    public function apply(Document $document, Certificate $certificate): Element
    {
        $reference = SecurityTokenReference::keyIdentifier($this->encodedValue, $this->valueType, $this->encodingType)
            ->build($document);

        return $document->map(namespaced_element(
            Namespaces::Ds->value,
            Namespaces::Ds->qualify('KeyInfo'),
            children(static fn (): Element => $reference),
        ));
    }
}
