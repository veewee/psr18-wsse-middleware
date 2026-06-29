<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;

/**
 * References a SAML assertion by its assertion id, for when the key is proved by an embedded assertion. The
 * result is ds:KeyInfo > wsse:SecurityTokenReference > wsse:KeyIdentifier with the SAMLAssertionID value type.
 * The assertion id is an XML id, not binary, so the KeyIdentifier carries no encoding type.
 */
final class SamlAssertionKeyIdentifier implements KeyIdentifierInterface
{
    /** @var non-empty-string */
    private string $samlAssertionId;

    /**
     * @param non-empty-string $samlAssertionId
     */
    public function __construct(string $samlAssertionId)
    {
        $this->samlAssertionId = $samlAssertionId;
    }

    public function apply(Document $document, Certificate $certificate): Element
    {
        return SecurityTokenReference::samlAssertion($this->samlAssertionId)->buildKeyInfo($document);
    }
}
