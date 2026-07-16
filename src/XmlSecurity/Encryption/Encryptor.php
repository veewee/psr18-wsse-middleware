<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\Manipulator\NodeOrder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdMinter;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\XmlIdMinter;
use Throwable;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Manipulator\append;

/**
 * Orchestrates the XML encryption flow for one request: resolve every target first (fail fast before any
 * mutation), generate one shared session key, encrypt and replace each target as xenc:EncryptedData, wrap the
 * session key under the recipient certificate, build one xenc:EncryptedKey carrying the ReferenceList, insert
 * it into the container element the caller supplies on the request and re-sort that container.
 *
 * The Encryptor does not locate or create the container (the caller does that and passes the element in — the
 * WS-Security profile hands over its wsse:Security header). No openssl_* calls live here: every cipher operation
 * goes through OpenSSL\Cipher and every key-wrap through OpenSSL\KeyTransport.
 */
final class Encryptor implements XmlEncryptor
{
    public static function create(?IdMinter $idMinter = null): self
    {
        return new self(
            new TargetLocator(),
            new SessionKeyFactory(),
            new Cipher(),
            new EncryptedDataBuilder($idMinter ?? new XmlIdMinter()),
            new KeyTransport(),
            new EncryptedKeyBuilder(),
        );
    }

    public function __construct(
        private readonly TargetLocator $targetLocator,
        private readonly SessionKeyFactory $sessionKeyFactory,
        private readonly Cipher $cipher,
        private readonly EncryptedDataBuilder $encryptedDataBuilder,
        private readonly KeyTransport $keyTransport,
        private readonly EncryptedKeyBuilder $encryptedKeyBuilder,
    ) {
    }

    public function encrypt(Document $document, EncryptionRequest $request): void
    {
        $container = $request->container;

        $targets = $this->resolveTargets($document, $request);

        try {
            $sessionKey = $this->sessionKeyFactory->generate($request->dataEncryptionMethod);

            $partIds = [];
            foreach ($targets as [$element, $mode]) {
                $plaintext = $this->serialize($document, $element, $mode);
                $cipherText = $this->cipher->encrypt($plaintext, $sessionKey, $request->dataEncryptionMethod);

                $partIds[] = $this->encryptedDataBuilder->build(
                    $document,
                    $element,
                    $cipherText,
                    $request->dataEncryptionMethod,
                    $mode,
                );
            }

            $wrappedKey = $this->keyTransport->wrap(
                $sessionKey,
                $request->recipientCertificate,
                $request->keyTransportAlgorithm,
            );

            $encryptedKey = $this->encryptedKeyBuilder->build(
                $document,
                $wrappedKey,
                $request->keyIdentifier,
                $request->recipientCertificate,
                $request->keyTransportAlgorithm,
                $partIds,
            );

            append($encryptedKey)($container);
            NodeOrder::sort($container);
        } catch (EncryptionFailed $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw EncryptionFailed::withReason($exception->getMessage());
        }
    }

    /**
     * @return non-empty-list<array{0: Element, 1: EncryptionMode}>
     *
     * @throws EncryptionFailed
     */
    private function resolveTargets(Document $document, EncryptionRequest $request): array
    {
        $resolved = [];
        foreach ($request->targets as $encryptionTarget) {
            try {
                $element = $this->targetLocator->locate($document, $encryptionTarget->target);
            } catch (IdReferenceException $exception) {
                throw EncryptionFailed::withReason($exception->getMessage());
            }

            $resolved[] = [$element, $encryptionTarget->mode];
        }

        return $resolved;
    }

    private function serialize(Document $document, Element $element, EncryptionMode $mode): string
    {
        if ($mode === EncryptionMode::Element) {
            return $document->stringifyNode($element);
        }

        $serialized = '';
        /** @var Node $child */
        foreach ($element->childNodes as $child) {
            $serialized .= $document->stringifyNode($child);
        }

        return $serialized;
    }
}
