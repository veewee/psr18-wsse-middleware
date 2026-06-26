<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec;

use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Request\DecryptionRequest;
use VeeWee\Xml\Dom\Document;

/**
 * Decrypts xenc:EncryptedData in the document in place. Implementations collapse every decryption failure to
 * one uniform error so the engine cannot become a padding or validation oracle for a peer.
 */
interface XmlDecryptor
{
    public function decrypt(Document $document, DecryptionRequest $request): void;
}
