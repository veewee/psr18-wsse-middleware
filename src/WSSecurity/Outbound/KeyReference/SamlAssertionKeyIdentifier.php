<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\SamlVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;

/**
 * References a SAML assertion by its assertion id, for when the key is proved by an embedded assertion. The
 * result is ds:KeyInfo > wsse:SecurityTokenReference > wsse:KeyIdentifier. The assertion id is an XML id, not
 * binary, so the KeyIdentifier carries no encoding type.
 *
 * The version is required because the two are referenced differently: SAML 2.0 has its own ValueType and the
 * profile requires a wsse11:TokenType naming the version, so a version-blind reference can only describe a
 * 1.1 assertion.
 */
final class SamlAssertionKeyIdentifier implements KeyIdentifierInterface
{
    /** @var non-empty-string */
    private string $samlAssertionId;

    private SamlVersion $version;

    /**
     * @param non-empty-string $samlAssertionId
     */
    public function __construct(string $samlAssertionId, SamlVersion $version)
    {
        $this->samlAssertionId = $samlAssertionId;
        $this->version = $version;
    }

    public function apply(Document $document): Element
    {
        return SecurityTokenReference::samlAssertion($this->samlAssertionId, $this->version)->buildKeyInfo($document);
    }
}
