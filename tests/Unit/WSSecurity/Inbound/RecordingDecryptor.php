<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\DecryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlDecryptor;
use VeeWee\Xml\Dom\Document;

/**
 * Captures the document and request the block hands to the decryptor so the unit-level tests can assert the
 * wiring without running the real crypto path. Never throws.
 */
final class RecordingDecryptor implements XmlDecryptor
{
    private ?Document $document = null;
    private ?DecryptionRequest $request = null;

    public function decrypt(Document $document, DecryptionRequest $request): void
    {
        $this->document = $document;
        $this->request = $request;
    }

    public function lastDocument(): ?Document
    {
        return $this->document;
    }

    public function lastRequest(): ?DecryptionRequest
    {
        return $this->request;
    }
}
