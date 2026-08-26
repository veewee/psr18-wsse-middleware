<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use VeeWee\Xml\Dom\Document;

/**
 * Encrypts the requested parts of the document in place (xenc:EncryptedData / EncryptedKey).
 *
 * Parts whose bytes are not in the document cannot be replaced in place, so their ciphertext comes back on the
 * result for the caller to store. The engine never writes them: it has no idea where they live, and handing it
 * something that could write them would put caller code inside a crypto operation.
 */
interface XmlEncryptor
{
    public function encrypt(Document $document, EncryptionRequest $request): EncryptionResult;
}
