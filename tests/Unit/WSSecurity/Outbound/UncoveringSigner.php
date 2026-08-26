<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\External\SignedExternalParts;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SigningRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\XmlSigner;
use VeeWee\Xml\Dom\Document;

/**
 * A signer that reports covering no external part at all, whatever it was handed.
 *
 * What a replaceable seam is free to do, and what the block has to notice: the caller asked for an
 * attachment to be signed and would otherwise send it believing it was.
 */
final class UncoveringSigner implements XmlSigner
{
    public function sign(Document $document, SigningRequest $request): SignedExternalParts
    {
        return new SignedExternalParts(ExternalPartList::of());
    }
}
