<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption;

use Soap\Psr18WsseMiddleware\WSSecurity\Exception\DecryptionFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\EncryptedData;
use Throwable;
use VeeWee\Xml\Dom\Document;

/**
 * Orchestrates the WSSE XML decryption flow for one request: count the declared data references and reject an
 * over-cap message before any crypto (a denial-of-service gate), unwrap the session key (which also refuses a
 * non-SHA-1 OAEP parameterization), then resolve and decrypt each referenced xenc:EncryptedData in place.
 *
 * Every failure, whatever its cause, collapses to one DecryptionFailed with a non-identifying message, so the
 * caller can never tell an OAEP refusal from a wrong key, a bad tag, a malformed value or an over-cap message;
 * the engine is never a padding or validation oracle. No openssl_* calls live here: unwrap goes through the
 * EncryptedKeyReader and decrypt through the EncryptedDataReader.
 */
final class Decryptor implements XmlDecryptor
{
    /**
     * The upper bound on xenc:DataReference entries a single xenc:ReferenceList may declare, a conservative
     * ceiling far above any legitimate WSSE message. Enforced before any unwrap or decrypt work.
     */
    public const int MAX_ENCRYPTED_PARTS = 32;

    public function __construct(
        private readonly EncryptedKeyReader $encryptedKeyReader,
        private readonly EncryptedDataReader $encryptedDataReader,
    ) {
    }

    public function decrypt(Document $document, DecryptionRequest $request): void
    {
        try {
            $references = $this->encryptedKeyReader->dataReferences($document);

            if (count($references) > self::MAX_ENCRYPTED_PARTS) {
                throw DecryptionFailed::withReason('The message declares too many encrypted parts.');
            }

            $sessionKey = $this->encryptedKeyReader->read($document, $request->privateKey, $request->profile);

            foreach ($references as $id) {
                $element = EncryptedData::resolve($document, $id);
                $this->encryptedDataReader->read($document, $element, $sessionKey);
            }
        } catch (Throwable) {
            // Every cause collapses to one message so the inbound path is never a padding or validation oracle.
            throw DecryptionFailed::withReason('Unable to decrypt the message.');
        }
    }
}
