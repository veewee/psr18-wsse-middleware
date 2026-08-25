<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use Dom\Node;
use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\XmlSecurity\AttributeIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use Throwable;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Manipulator\append;

/**
 * Orchestrates the XML encryption flow for one request: resolve every target first (fail fast before any
 * mutation), generate one shared session key, encrypt and replace each target as xenc:EncryptedData, wrap the
 * session key under the recipient certificate, build one xenc:EncryptedKey carrying the ReferenceList, insert
 * it into the container element the caller supplies on the request and re-sort that container.
 *
 * The Encryptor does not locate or create the container (the caller does that and passes the element in: the
 * WS-Security profile hands over its wsse:Security header). No openssl_* calls live here: every cipher operation
 * goes through OpenSSL\Cipher and every key-wrap through OpenSSL\KeyTransport.
 */
final class Encryptor implements XmlEncryptor
{
    /**
     * The id convention is taken as a pair: the minter stamps the xenc:EncryptedData id and the lookup resolves
     * a by-id encryption target, so two that disagree would leave a DataReference pointing at nothing. Defaults
     * to the engine's xml:id; the WS-Security profile hands over its wsu:Id convention.
     */
    public static function create(?IdConvention $idConvention = null): self
    {
        $idConvention ??= AttributeIdConvention::xmlId();

        return new self(
            new TargetLocator($idConvention->lookup()),
            new SessionKeyFactory(),
            new Cipher(),
            new EncryptedDataBuilder($idConvention->minter()),
            new KeyTransport(),
            new EncryptedKeyBuilder(),
            new ExternalEncryptedDataBuilder($idConvention->minter()),
        );
    }

    public function __construct(
        private readonly TargetLocator $targetLocator,
        private readonly SessionKeyFactory $sessionKeyFactory,
        private readonly Cipher $cipher,
        private readonly EncryptedDataBuilder $encryptedDataBuilder,
        private readonly KeyTransport $keyTransport,
        private readonly EncryptedKeyBuilder $encryptedKeyBuilder,
        private readonly ExternalEncryptedDataBuilder $externalEncryptedDataBuilder,
    ) {
    }

    public function encrypt(Document $document, EncryptionRequest $request): EncryptionResult
    {
        $container = $request->container;

        $targets = $this->resolveTargets($document, $request);
        $externalParts = $request->externalParts?->parts ?? ExternalPartList::of();

        // The rule is "encrypt at least one part", not "at least one in-document part". A message with
        // nothing to encrypt would emit an EncryptedKey whose ReferenceList names nothing, which reads as an
        // encrypted message while protecting none of it.
        if ($targets === [] && count($externalParts) === 0) {
            throw EncryptionFailed::withReason('An encryption request must name at least one part.');
        }

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

            // Under the same session key, contributing to the same ReferenceList. The SwA profile wants one
            // EncryptedKey naming the in-document parts and the attachment parts together, and
            // EncryptedKeyReader refuses a second key in the container, so this cannot be a separate
            // operation alongside the first.
            $sealed = [];
            foreach ($externalParts as $part) {
                $sealed[] = $this->sealExternalPart($document, $part, $request, $sessionKey, $container, $partIds);
            }

            $wrappedKey = $this->keyTransport->wrap(
                $sessionKey,
                $request->recipientCertificate,
                $request->keyTransportAlgorithm,
            );

            if ($partIds === []) {
                // The ReferenceList invariant, checked rather than assumed: every id in it came from work done
                // above, so an empty list here would mean an EncryptedKey unlocking nothing. The request guard
                // makes this unreachable, and a static constraint is not a runtime check.
                throw EncryptionFailed::withReason('An encryption request must name at least one part.');
            }

            $encryptedKey = $this->encryptedKeyBuilder->build(
                $document,
                $wrappedKey,
                $request->keyIdentifier,
                $request->recipientCertificate,
                $request->keyTransportAlgorithm,
                $partIds,
            );

            append($encryptedKey)($container);

            return new EncryptionResult(ExternalPartList::of(...$sealed));
        } catch (EncryptionFailed $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw EncryptionFailed::withReason($exception->getMessage());
        }
    }

    /**
     * Encrypts one external part, appends its xenc:EncryptedData to the container, records its id for the
     * ReferenceList, and returns the sealed part.
     *
     * @param list<non-empty-string> $partIds appended to in place, so external ids join the in-document ones
     *        in the single ReferenceList rather than forming a second one
     *
     * @throws EncryptionFailed
     */
    private function sealExternalPart(
        Document $document,
        ExternalPart $part,
        EncryptionRequest $request,
        SessionKey $sessionKey,
        Element $container,
        array &$partIds,
    ): ExternalPart {
        $external = $request->externalParts;
        if ($external === null) {
            throw EncryptionFailed::withReason('An external part was supplied without its profile facts.');
        }

        $plaintext = $part->content->rewind()->getContents();
        if ($plaintext === '') {
            // A stream already consumed elsewhere looks exactly like this. Encrypting it would produce a
            // ciphertext that decrypts to nothing and still passes every structural check, so the caller would
            // ship an empty file believing it was protected. Sign-then-encrypt reads each part twice, which is
            // how a non-rewinding adapter arrives here.
            throw EncryptionFailed::withReason('An external part read zero bytes.');
        }

        $cipherText = $this->cipher->encrypt($plaintext, $sessionKey, $request->dataEncryptionMethod);

        [$encryptedData, $id] = $this->externalEncryptedDataBuilder->build(
            $document,
            $part,
            $cipherText,
            $request->dataEncryptionMethod,
            $external->type,
            $external->transform,
        );

        append($encryptedData)($container);
        $partIds[] = $id;

        // The same framing EncryptedDataBuilder base64s into a CipherValue, only unencoded: the MIME layer
        // carries the bytes, so there is nothing to escape them for.
        return $part->withContent(
            $this->stream($cipherText->iv.$cipherText->bytes.($cipherText->tag ?? '')),
            $part->mimeType,
        );
    }

    /**
     * @return ResourceStream<resource>
     */
    private function stream(string $bytes): ResourceStream
    {
        return MemoryStream::create()->write($bytes)->rewind();
    }

    /**
     * @return list<array{0: Element, 1: EncryptionMode}>
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
