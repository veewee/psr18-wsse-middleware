<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use LogicException;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Request\SigningRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\XmlSigner;
use VeeWee\Xml\Dom\Document;

/**
 * Captures the SigningRequest the block builds so the unit-level tests can assert its shape without
 * running the real crypto path.
 */
final class RecordingSigner implements XmlSigner
{
    private ?SigningRequest $request = null;

    public function sign(Document $document, SigningRequest $request): void
    {
        $this->request = $request;
    }

    public function lastRequest(): SigningRequest
    {
        if ($this->request === null) {
            throw new LogicException('sign() was not called.');
        }

        return $this->request;
    }
}
