<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External;

use Dom\Element;
use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\Encryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Manipulator\append;

/**
 * Seals a message's external parts under a session key the caller already generated: each part's bytes are
 * replaced by ciphertext, and an xenc:EncryptedData describing it is appended to the container.
 *
 * Separate from Encryptor because the two protect different things. Encryptor replaces nodes in a document it
 * owns; this replaces bytes that never enter the document, and reports the ids it minted so its parts join the
 * one ReferenceList rather than forming a second one.
 */
final readonly class ExternalPartSealer
{
    public function __construct(
        private Cipher $cipher,
        private ExternalEncryptedDataBuilder $builder,
    ) {
    }

    /**
     * @throws EncryptionFailed
     */
    public function seal(
        Document $document,
        Element $container,
        ExternalPartEncryption $external,
        SessionKey $sessionKey,
        DataEncryptionMethod $method,
    ): SealedExternalParts {
        $sealed = [];
        $ids = [];

        foreach ($external->parts as $part) {
            [$sealed[], $ids[]] = $this->sealOne($document, $container, $part, $external, $sessionKey, $method);
        }

        return new SealedExternalParts(ExternalPartList::of(...$sealed), $ids);
    }

    /**
     * @return array{0: ExternalPart, 1: non-empty-string}
     *
     * @throws EncryptionFailed
     */
    private function sealOne(
        Document $document,
        Element $container,
        ExternalPart $part,
        ExternalPartEncryption $external,
        SessionKey $sessionKey,
        DataEncryptionMethod $method,
    ): array {
        $plaintext = $part->content->rewind()->getContents();
        if ($plaintext === '') {
            // Encrypting nothing produces a ciphertext that decrypts to nothing and still passes every
            // structural check, so the caller would ship an empty file believing it was protected. A part
            // whose stream cannot rewind reads this way too.
            throw EncryptionFailed::withReason('An external part read zero bytes.');
        }

        $cipherText = $this->cipher->encrypt($plaintext, $sessionKey, $method);

        [$encryptedData, $id] = $this->builder->build(
            $document,
            $part,
            $cipherText,
            $method,
            $external->type,
            $external->transform,
        );

        append($encryptedData)($container);

        // The same framing EncryptedDataBuilder base64s into a CipherValue, only unencoded: the MIME layer
        // carries the bytes, so there is nothing to escape them for.
        return [
            $part->withContent(
                $this->stream($cipherText->iv.$cipherText->bytes.($cipherText->tag ?? '')),
                $part->mimeType,
            ),
            $id,
        ];
    }

    /**
     * @return ResourceStream<resource>
     */
    private function stream(string $bytes): ResourceStream
    {
        return MemoryStream::create()->write($bytes)->rewind();
    }
}
