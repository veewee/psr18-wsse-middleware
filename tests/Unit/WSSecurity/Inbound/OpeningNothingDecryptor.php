<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\DecryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\DecryptionResult;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlDecryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use VeeWee\Xml\Dom\Document;

/**
 * A decryptor that opens no external part, whatever it was handed.
 *
 * Stands in for the message this guards against: one whose xenc:EncryptedData names only in-document parts,
 * leaving a registered attachment to arrive in the clear.
 */
final class OpeningNothingDecryptor implements XmlDecryptor
{
    public function decrypt(Document $document, DecryptionRequest $request): DecryptionResult
    {
        return new DecryptionResult(ExternalPartList::of());
    }
}
