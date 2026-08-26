<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Phpro\ResourceStream\Factory\MemoryStream;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\DecryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\DecryptionResult;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlDecryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use VeeWee\Xml\Dom\Document;

/**
 * Captures the document and request the block hands to the decryptor so the unit-level tests can assert the
 * wiring without running the real crypto path. Never throws.
 */
final class RecordingDecryptor implements XmlDecryptor
{
    private ?Document $document = null;
    private ?DecryptionRequest $request = null;

    public function decrypt(Document $document, DecryptionRequest $request): DecryptionResult
    {
        $this->document = $document;
        $this->request = $request;

        // Stands in for real plaintext: every supplied part comes back opened under its own reference, which
        // is what the block then writes to the store.
        $opened = [];
        foreach ($request->externalParts?->parts ?? ExternalPartList::of() as $part) {
            $opened[] = new ExternalPart(
                $part->reference,
                $part->mimeType,
                MemoryStream::create()->write('opened:'.$part->content->rewind()->getContents())->rewind(),
            );
        }

        return new DecryptionResult(ExternalPartList::of(...$opened));
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
