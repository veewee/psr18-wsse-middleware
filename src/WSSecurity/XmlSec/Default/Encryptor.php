<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default;

use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\EncryptionFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\PartKind;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\NodeOrder;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseXpath;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Request\EncryptionRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\XmlEncryptor;
use Throwable;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Manipulator\append;

/**
 * Orchestrates the WSSE XML encryption flow for one request: resolve every Part first (fail fast before any
 * mutation), generate one shared session key, encrypt and replace each Part as xenc:EncryptedData, wrap the
 * session key under the recipient certificate, build one xenc:EncryptedKey carrying the ReferenceList, insert
 * it into the existing wsse:Security header and re-sort the header.
 *
 * The Encryptor does not create the Security header (the outbound caller does that before encrypt() runs, as
 * for signing); it only locates the existing element and throws EncryptionFailed when it is absent. No
 * openssl_* calls live here: every cipher operation goes through OpenSSL\Cipher and every key-wrap through
 * OpenSSL\KeyTransport.
 */
final class Encryptor implements XmlEncryptor
{
    public function __construct(
        private readonly PartLocator $partLocator,
        private readonly SessionKeyFactory $sessionKeyFactory,
        private readonly Cipher $cipher,
        private readonly EncryptedDataBuilder $encryptedDataBuilder,
        private readonly KeyTransport $keyTransport,
        private readonly EncryptedKeyBuilder $encryptedKeyBuilder,
    ) {
    }

    public function encrypt(Document $document, EncryptionRequest $request): void
    {
        $security = $this->locateSecurity($document);

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
                $this->recipientCertificate($request),
                $request->keyEncryptionMethod,
            );

            $encryptedKey = $this->encryptedKeyBuilder->build(
                $document,
                $wrappedKey,
                $request->keyIdentifier,
                $this->recipientCertificate($request),
                $request->keyEncryptionMethod,
                $partIds,
            );

            append($encryptedKey)($security);
            NodeOrder::sort($security);
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
        $targets = [];
        foreach ($request->parts as $part) {
            try {
                $element = $this->partLocator->locate($document, $part);
            } catch (IdReferenceException $exception) {
                throw EncryptionFailed::withReason($exception->getMessage());
            }

            $targets[] = [$element, $this->modeFor($part)];
        }

        return $targets;
    }

    private function modeFor(Part $part): EncryptionMode
    {
        // The SOAP Body and the Timestamp are encrypted as Content (the element survives, its children are
        // replaced); a targeted header element is encrypted whole as Element.
        return match ($part->kind()) {
            PartKind::Body, PartKind::Timestamp => EncryptionMode::Content,
            PartKind::Element, PartKind::Id => EncryptionMode::Element,
        };
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

    /**
     * @throws EncryptionFailed
     */
    private function recipientCertificate(EncryptionRequest $request): Certificate
    {
        $material = $request->recipientCertificate->material();
        if (!$material instanceof Certificate) {
            throw EncryptionFailed::withReason('The recipient key handle does not carry certificate material.');
        }

        return $material;
    }

    /**
     * @throws EncryptionFailed
     */
    private function locateSecurity(Document $document): Element
    {
        $security = $document
            ->xpath(new WsseXpath($document))
            ->query('//'.WsseNamespace::Wsse->qualify('Security'))
            ->expectAllOfType(Element::class)
            ->first();

        if ($security === null) {
            throw EncryptionFailed::withReason('No wsse:Security header was found to attach the encrypted key to.');
        }

        return $security;
    }
}
