<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use VeeWee\Xml\Dom\Document;

/**
 * Encrypts the requested parts of the document in place (xenc:EncryptedData / EncryptedKey).
 */
interface XmlEncryptor
{
    public function encrypt(Document $document, EncryptionRequest $request): void;
}
