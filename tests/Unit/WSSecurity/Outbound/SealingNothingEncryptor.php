<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionResult;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlEncryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use VeeWee\Xml\Dom\Document;

/**
 * An encryptor that seals no external part, whatever it was handed.
 *
 * What the block has to notice: the message carries an xenc:EncryptedKey and reads as encrypted, while the
 * attachment the caller registered is still sitting in the storage as plaintext.
 */
final class SealingNothingEncryptor implements XmlEncryptor
{
    public function encrypt(Document $document, EncryptionRequest $request): EncryptionResult
    {
        return new EncryptionResult(ExternalPartList::of());
    }
}
