<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\AttributeIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdAttribute;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdMinter;

/**
 * The WS-Security profile's id convention: wsu:Id, as the spec mandates. The blocks hand this to the engine so
 * signed and encrypted parts carry wsu:Id and every reference resolves through the same attribute.
 *
 * It lives in the WSSE layer, not beside the engine's own default, because the engine has no business knowing
 * the WS-Security namespaces: supplying the attribute from here is what keeps it that way.
 */
final readonly class WsuIdConvention implements IdConvention
{
    private AttributeIdConvention $convention;
    private WsuIdLookup $lookup;

    public function __construct()
    {
        $this->convention = new AttributeIdConvention(
            IdAttribute::of(WsseNamespaces::Wsu->value, WsseNamespaces::Wsu->qualify('Id')),
        );
        $this->lookup = new WsuIdLookup();
    }

    public function minter(): IdMinter
    {
        return $this->convention->minter();
    }

    /**
     * Reading is wider than writing by exactly one attribute: a ds:Signature also answers to the native Id that
     * XML Signature declares on it, because a peer covering a signature names it that way and nothing this
     * package stamps would be found otherwise. See WsuIdLookup.
     */
    public function lookup(): IdLookup
    {
        return $this->lookup;
    }
}
