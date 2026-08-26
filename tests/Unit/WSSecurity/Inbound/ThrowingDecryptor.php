<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\DecryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlDecryptor;
use Throwable;
use VeeWee\Xml\Dom\Document;

/**
 * Throws a fixed exception on decrypt so the tests can exercise the fault-mapping arms of the block.
 */
final class ThrowingDecryptor implements XmlDecryptor
{
    public function __construct(private readonly Throwable $failure)
    {
    }

    public function decrypt(Document $document, DecryptionRequest $request): void
    {
        throw $this->failure;
    }
}
