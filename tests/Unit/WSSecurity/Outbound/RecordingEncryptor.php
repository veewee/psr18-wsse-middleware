<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use LogicException;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Request\EncryptionRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\XmlEncryptor;
use VeeWee\Xml\Dom\Document;

/**
 * Captures the EncryptionRequest the block builds so the unit-level tests can assert its shape without
 * running the real crypto path.
 */
final class RecordingEncryptor implements XmlEncryptor
{
    private ?EncryptionRequest $request = null;

    public function encrypt(Document $document, EncryptionRequest $request): void
    {
        $this->request = $request;
    }

    public function lastRequest(): EncryptionRequest
    {
        if ($this->request === null) {
            throw new LogicException('encrypt() was not called.');
        }

        return $this->request;
    }
}
