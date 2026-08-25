<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use LogicException;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\External\SignedExternalParts;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SigningRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\XmlSigner;
use VeeWee\Xml\Dom\Document;

/**
 * Captures the SigningRequest the block builds so the unit-level tests can assert its shape without
 * running the real crypto path.
 */
final class RecordingSigner implements XmlSigner
{
    private ?SigningRequest $request = null;

    public function sign(Document $document, SigningRequest $request): SignedExternalParts
    {
        $this->request = $request;

        // Reports back exactly what it was handed, which is what a real signer that covered everything does.
        // A test wanting to see the block react to incomplete coverage builds its own double.
        return new SignedExternalParts($request->externalParts?->parts ?? ExternalPartList::of());
    }

    public function lastRequest(): SigningRequest
    {
        if ($this->request === null) {
            throw new LogicException('sign() was not called.');
        }

        return $this->request;
    }
}
