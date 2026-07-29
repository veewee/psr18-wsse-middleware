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
 * the WS-Security namespaces — supplying the attribute from here is what keeps it that way.
 */
final readonly class WsuIdConvention implements IdConvention
{
    private AttributeIdConvention $convention;

    public function __construct()
    {
        $this->convention = new AttributeIdConvention(
            IdAttribute::of(Namespaces::Wsu->value, Namespaces::Wsu->qualify('Id')),
        );
    }

    public function minter(): IdMinter
    {
        return $this->convention->minter();
    }

    public function lookup(): IdLookup
    {
        return $this->convention->lookup();
    }
}
