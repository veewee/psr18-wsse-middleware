<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Wsse;

use Closure;
use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * A wsse:SecurityTokenReference: the element that tells a verifier where the key for a signature or
 * encryption lives. The four variants cover the ways the WS-Security spec allows a key to be pointed
 * at, and differ only in their single child element. A typed value object sealed at construction; the
 * caller computes the encoded values (the key-identifier strategies fill them in) and build()
 * materialises the element.
 */
final readonly class SecurityTokenReference
{
    /**
     * @param Closure(Node): Element $childBuilder builds the single child of the wsse:SecurityTokenReference
     */
    private function __construct(
        private Closure $childBuilder,
    ) {
    }

    /**
     * Reference variant: points at an in-document token by its wsu:Id. build() emits URI="#<id>".
     *
     * @param non-empty-string $uri the wsu:Id of the referenced token, without the '#'
     * @param non-empty-string $valueType the token's WS-Security ValueType URI
     */
    public static function reference(string $uri, string $valueType): self
    {
        return new self(namespaced_element(
            WsseNamespace::Wsse->value,
            WsseNamespace::Wsse->qualify('Reference'),
            attribute('URI', '#'.$uri),
            attribute('ValueType', $valueType),
        ));
    }

    /**
     * KeyIdentifier variant: carries an encoded identifier of the key (SKI, thumbprint, ...).
     *
     * @param non-empty-string $encodedValue the base64-encoded identifier
     * @param non-empty-string $valueType the identifier's WS-Security ValueType URI
     * @param non-empty-string $encodingType the encoding URI (typically Base64Binary)
     */
    public static function keyIdentifier(string $encodedValue, string $valueType, string $encodingType): self
    {
        return new self(namespaced_element(
            WsseNamespace::Wsse->value,
            WsseNamespace::Wsse->qualify('KeyIdentifier'),
            attribute('ValueType', $valueType),
            attribute('EncodingType', $encodingType),
            value($encodedValue),
        ));
    }

    /**
     * Embedded variant: wraps an inline token element (such as a SAML assertion).
     *
     * @param callable(Node): Element $childBuilder builds the embedded token element
     */
    public static function embedded(callable $childBuilder): self
    {
        return new self(namespaced_element(
            WsseNamespace::Wsse->value,
            WsseNamespace::Wsse->qualify('Embedded'),
            children($childBuilder),
        ));
    }

    /**
     * KeyName variant: names the key with a ds:KeyName.
     *
     * @param non-empty-string $name
     */
    public static function keyName(string $name): self
    {
        return new self(namespaced_element(
            WsseNamespace::Ds->value,
            WsseNamespace::Ds->qualify('KeyName'),
            value($name),
        ));
    }

    /**
     * X509IssuerSerial variant: points at the key by the certificate's issuer DN and serial number,
     * carried as a ds:X509Data child as required by the WS-Security X.509 token profile.
     *
     * @param non-empty-string $issuerName the issuer distinguished name
     * @param non-empty-string $serialNumber the certificate serial number in decimal
     */
    public static function x509IssuerSerial(string $issuerName, string $serialNumber): self
    {
        return new self(namespaced_element(
            WsseNamespace::Ds->value,
            WsseNamespace::Ds->qualify('X509Data'),
            children(namespaced_element(
                WsseNamespace::Ds->value,
                WsseNamespace::Ds->qualify('X509IssuerSerial'),
                children(
                    namespaced_element(
                        WsseNamespace::Ds->value,
                        WsseNamespace::Ds->qualify('X509IssuerName'),
                        value($issuerName),
                    ),
                    namespaced_element(
                        WsseNamespace::Ds->value,
                        WsseNamespace::Ds->qualify('X509SerialNumber'),
                        value($serialNumber),
                    ),
                ),
            )),
        ));
    }

    public function build(Document $document): Element
    {
        return $document->map(namespaced_element(
            WsseNamespace::Wsse->value,
            WsseNamespace::Wsse->qualify('SecurityTokenReference'),
            children($this->childBuilder),
        ));
    }
}
