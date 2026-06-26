<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy;

use Dom\Element;
use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * References a SAML assertion by its assertion id, for when the key is proved by an embedded assertion. The
 * result is ds:KeyInfo > wsse:SecurityTokenReference > wsse:KeyIdentifier with the SAMLAssertionID value type.
 * The assertion id is an XML id, not binary, so the KeyIdentifier carries no encoding type.
 */
final class SamlAssertionKeyIdentifier implements KeyIdentifierInterface
{
    private const VALUE_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID';

    /** @var non-empty-string */
    private string $samlAssertionId;

    public function __construct(string $samlAssertionId)
    {
        if ($samlAssertionId === '') {
            throw new InvalidArgumentException('A SAML assertion reference requires a non-empty assertion id.');
        }

        $this->samlAssertionId = $samlAssertionId;
    }

    public function apply(Document $document, Certificate $certificate): Element
    {
        return $document->map(namespaced_element(
            WsseNamespace::Ds->value,
            WsseNamespace::Ds->qualify('KeyInfo'),
            children(namespaced_element(
                WsseNamespace::Wsse->value,
                WsseNamespace::Wsse->qualify('SecurityTokenReference'),
                children(namespaced_element(
                    WsseNamespace::Wsse->value,
                    WsseNamespace::Wsse->qualify('KeyIdentifier'),
                    attribute('ValueType', self::VALUE_TYPE),
                    value($this->samlAssertionId),
                )),
            )),
        ));
    }
}
