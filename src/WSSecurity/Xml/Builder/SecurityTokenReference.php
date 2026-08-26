<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder;

use Closure;
use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\SamlVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityEncodingType;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityValueType;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespaces;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_attribute;
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
     * @param non-empty-string|null $tokenType the wsse11:TokenType naming the referenced token's type, for the
     *        reference kinds whose profile calls for it
     */
    private function __construct(
        private Closure $childBuilder,
        private ?string $tokenType = null,
    ) {
    }

    /**
     * Reference variant: points at an in-document token by its wsu:Id. build() emits URI="#<id>".
     *
     * @param non-empty-string $uri the wsu:Id of the referenced token, without the '#'
     * @param non-empty-string $valueType the token's WS-Security ValueType URI
     * @param non-empty-string|null $tokenType the wsse11:TokenType the referenced token's profile calls for
     */
    public static function reference(string $uri, string $valueType, ?string $tokenType = null): self
    {
        return new self(
            namespaced_element(
                WsseNamespaces::Wsse->value,
                WsseNamespaces::Wsse->qualify('Reference'),
                attribute('URI', '#'.$uri),
                attribute('ValueType', $valueType),
            ),
            $tokenType,
        );
    }

    /**
     * Local-reference variant: points at an element this same Security header carries, by its wsu:Id.
     *
     * The ValueType is optional because not every referenced element has one, but pass it where the element's
     * own profile defines one: a receiver enforcing the Basic Security Profile classifies a reference by its
     * declared type, and refuses one it cannot classify rather than looking at what it points at.
     *
     * @param non-empty-string      $uri       the wsu:Id of the referenced element, without the '#'
     * @param non-empty-string|null $valueType the referenced element's own type URI, when its profile names one
     */
    public static function localReference(string $uri, ?string $valueType = null): self
    {
        return new self(namespaced_element(
            WsseNamespaces::Wsse->value,
            WsseNamespaces::Wsse->qualify('Reference'),
            attribute('URI', '#'.$uri),
            $valueType === null
                ? static fn (Element $reference): Element => $reference
                : attribute('ValueType', $valueType),
        ));
    }

    /**
     * KeyIdentifier variant: carries an encoded identifier of the key (SKI, thumbprint, ...).
     *
     * @param non-empty-string      $encodedValue the base64-encoded identifier
     * @param non-empty-string      $valueType    the identifier's WS-Security ValueType URI
     * @param non-empty-string      $encodingType the encoding URI (typically Base64Binary)
     * @param non-empty-string|null $tokenType    the wsse11:TokenType naming what the identifier points at, for
     *        the identifier kinds whose profile calls for it
     */
    public static function keyIdentifier(
        string $encodedValue,
        string $valueType,
        string $encodingType,
        ?string $tokenType = null,
    ): self {
        return new self(
            namespaced_element(
                WsseNamespaces::Wsse->value,
                WsseNamespaces::Wsse->qualify('KeyIdentifier'),
                attribute('ValueType', $valueType),
                attribute('EncodingType', $encodingType),
                value($encodedValue),
            ),
            $tokenType,
        );
    }

    /**
     * Thumbprint variant: a wsse:KeyIdentifier carrying the SHA-1 fingerprint of the certificate. Only the
     * ValueType URI belongs to WSS 1.1; the element itself stays in WSSE 1.0, which is where KeyIdentifier is
     * declared and how the X.509 Token Profile prints this reference. A peer resolves it by that 1.0 qualified
     * name, so emitting it in the 1.1 namespace would leave the reference unresolvable.
     *
     * @param non-empty-string $encodedValue the base64-encoded fingerprint
     */
    public static function thumbprint(string $encodedValue): self
    {
        return new self(namespaced_element(
            WsseNamespaces::Wsse->value,
            WsseNamespaces::Wsse->qualify('KeyIdentifier'),
            attribute('ValueType', WsSecurityValueType::ThumbprintSha1->value),
            attribute('EncodingType', WsSecurityEncodingType::Base64Binary->value),
            value($encodedValue),
        ));
    }

    /**
     * SAML assertion variant: a wsse:KeyIdentifier naming a SAML assertion by its id. The id is an XML id,
     * not binary, so the KeyIdentifier carries no encoding type.
     *
     * The ValueType is version-specific and the reference also carries a wsse11:TokenType naming the version:
     * the profile requires that for a SAML 2.0 assertion, whose ValueType the 1.0 profile could not express.
     *
     * @param non-empty-string $assertionId
     */
    public static function samlAssertion(string $assertionId, SamlVersion $version): self
    {
        return new self(
            namespaced_element(
                WsseNamespaces::Wsse->value,
                WsseNamespaces::Wsse->qualify('KeyIdentifier'),
                attribute('ValueType', $version->keyIdentifierValueType()->value),
                value($assertionId),
            ),
            $version->tokenType(),
        );
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
            Namespaces::Ds->value,
            Namespaces::Ds->qualify('X509Data'),
            children(namespaced_element(
                Namespaces::Ds->value,
                Namespaces::Ds->qualify('X509IssuerSerial'),
                children(
                    namespaced_element(
                        Namespaces::Ds->value,
                        Namespaces::Ds->qualify('X509IssuerName'),
                        value($issuerName),
                    ),
                    namespaced_element(
                        Namespaces::Ds->value,
                        Namespaces::Ds->qualify('X509SerialNumber'),
                        value($serialNumber),
                    ),
                ),
            )),
        ));
    }

    public function build(Document $document): Element
    {
        $tokenType = $this->tokenType;
        $stampTokenType = $tokenType === null
            ? static fn (Element $reference): Element => $reference
            : namespaced_attribute(
                WsseNamespaces::Wsse11->value,
                WsseNamespaces::Wsse11->qualify('TokenType'),
                $tokenType,
            );

        return $document->map(namespaced_element(
            WsseNamespaces::Wsse->value,
            WsseNamespaces::Wsse->qualify('SecurityTokenReference'),
            children($this->childBuilder),
            $stampTokenType,
        ));
    }

    /**
     * Builds the reference wrapped in the ds:KeyInfo a ds:Signature or xenc:EncryptedKey expects, the form
     * every key-identifier strategy hands back.
     */
    public function buildKeyInfo(Document $document): Element
    {
        $reference = $this->build($document);

        return $document->map(namespaced_element(
            Namespaces::Ds->value,
            Namespaces::Ds->qualify('KeyInfo'),
            children(static fn (): Element => $reference),
        ));
    }
}
