<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use LogicException;
use Phpro\ResourceStream\Factory\MemoryStream;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionResult;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlEncryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use VeeWee\Xml\Dom\Document;

/**
 * Captures the EncryptionRequest the block builds so the unit-level tests can assert its shape without
 * running the real crypto path.
 */
final class RecordingEncryptor implements XmlEncryptor
{
    private ?EncryptionRequest $request = null;

    public function encrypt(Document $document, EncryptionRequest $request): EncryptionResult
    {
        $this->request = $request;

        // Stands in for real ciphertext: every part comes back sealed under its own reference, which is what
        // the block then writes to the store. A test wanting to see the block react to a missing part builds
        // its own double.
        $sealed = [];
        foreach ($request->externalParts?->parts ?? ExternalPartList::of() as $part) {
            $sealed[] = new ExternalPart(
                $part->reference,
                $part->mimeType,
                MemoryStream::create()->write('sealed:'.$part->content->rewind()->getContents())->rewind(),
            );
        }

        return new EncryptionResult(ExternalPartList::of(...$sealed));
    }

    public function lastRequest(): EncryptionRequest
    {
        if ($this->request === null) {
            throw new LogicException('encrypt() was not called.');
        }

        return $this->request;
    }
}
