<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\XmlSecurity\AttributeIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External\ExternalEncryptedDataReader;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\DecryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Throwable;
use VeeWee\Xml\Dom\Document;

/**
 * Orchestrates the XML decryption flow for one request: count the declared data references and reject an
 * over-cap message before any crypto (a denial-of-service gate), unwrap the session key (which also refuses a
 * non-SHA-1 OAEP parameterization), then resolve and decrypt each referenced xenc:EncryptedData in place.
 *
 * The wrapped key and the reference list are read from the container the request names, so only the parts that
 * container claims are decrypted. The referenced xenc:EncryptedData themselves are resolved document-wide, as
 * they must be: encrypted content sits where it belongs in the message (most often in the Body) not inside
 * the container. Their ids resolve to exactly one element or the message is refused, so a planted duplicate
 * cannot stand in for a genuine part.
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
     * ceiling far above any legitimate message. Enforced before any unwrap or decrypt work.
     */
    public const int MAX_ENCRYPTED_PARTS = 32;

    /**
     * The id lookup resolves each xenc:DataReference to its xenc:EncryptedData. It defaults to the engine's
     * xml:id convention; the WS-Security profile injects the wsu:Id implementation.
     */
    public static function create(?IdLookup $idLookup = null): self
    {
        return new self(
            new EncryptedKeyReader(new KeyTransport()),
            new EncryptedDataReader(new Cipher()),
            new EncryptedDataLocator($idLookup ?? AttributeIdConvention::xmlId()->lookup()),
            new ExternalEncryptedDataReader(new Cipher()),
        );
    }

    public function __construct(
        private readonly EncryptedKeyReader $encryptedKeyReader,
        private readonly EncryptedDataReader $encryptedDataReader,
        private readonly EncryptedDataLocator $encryptedData,
        private readonly ExternalEncryptedDataReader $externalEncryptedDataReader,
    ) {
    }

    public function decrypt(Document $document, DecryptionRequest $request): DecryptionResult
    {
        try {
            $references = $this->encryptedKeyReader->dataReferences($document, $request->container);

            if (count($references) > self::MAX_ENCRYPTED_PARTS) {
                throw DecryptionFailed::withReason('The message declares too many encrypted parts.');
            }

            $sessionKey = $this->encryptedKeyReader->read(
                $document,
                $request->container,
                $request->privateKey,
                $request->policy,
            );

            $opened = [];
            foreach ($references as $id) {
                $element = $this->encryptedData->resolve($document, $id);

                // Which path a part takes is decided by the element, not by configuration: one carrying a
                // CipherReference has its bytes elsewhere and cannot be replaced in place. An encrypted
                // attachment is therefore never silently skipped, because a message naming one when no parts
                // were supplied is refused rather than ignored.
                if (!$this->externalEncryptedDataReader->supports($element)) {
                    $this->encryptedDataReader->read($document, $element, $sessionKey, $request->policy);

                    continue;
                }

                $external = $request->externalParts
                    ?? throw DecryptionFailed::withReason('The message encrypts a part that was not supplied.');

                $opened[] = $this->externalEncryptedDataReader->read(
                    $element,
                    $external,
                    $sessionKey,
                    $request->policy,
                );
            }

            return new DecryptionResult(ExternalPartList::of(...$opened));
        } catch (Throwable $exception) {
            // Every cause collapses to one message so the inbound path is never a padding or validation oracle.
            throw DecryptionFailed::withReason('Unable to decrypt the message.', $exception);
        }
    }
}
