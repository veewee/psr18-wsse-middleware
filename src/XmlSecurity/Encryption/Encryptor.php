<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\XopInclude;
use Soap\Psr18WsseMiddleware\XmlSecurity\AttributeIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External\ExternalEncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External\ExternalPartSealer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External\SealedExternalParts;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use Throwable;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Manipulator\append;

/**
 * Orchestrates the XML encryption flow for one request: resolve every target first (fail fast before any
 * mutation), encrypt and replace each target as xenc:EncryptedData under the session key the request carries,
 * and append one xenc:ReferenceList naming them all where the request says it goes: the container, or the
 * element carrying the key.
 *
 * How the session key reaches the recipient is not decided here. The caller has already established it, which
 * is what lets one key protect both a signature and an encryption; this class only spends it.
 *
 * The Encryptor does not locate or create the container (the caller does that and passes the element in: the
 * WS-Security profile hands over its wsse:Security header). No openssl_* calls live here: every cipher operation
 * goes through OpenSSL\Cipher.
 */
final class Encryptor implements XmlEncryptor
{
    /**
     * The id convention is taken as a pair: the minter stamps the xenc:EncryptedData id and the lookup resolves
     * a by-id encryption target, so two that disagree would leave a DataReference pointing at nothing. Defaults
     * to the engine's xml:id; the WS-Security profile hands over its wsu:Id convention.
     *
     * A sink moves the cipher bytes out of the document and leaves a pointer at them. Without one, which is
     * the default, both cipher values are base64 in the document as they always were.
     */
    public static function create(
        ?IdConvention $idConvention = null,
        ?CipherValueSink $cipherValueSink = null,
    ): self {
        $idConvention ??= AttributeIdConvention::xmlId();
        $cipher = new Cipher();
        $cipherValueElement = new CipherValueElement($cipherValueSink);

        return new self(
            new TargetLocator($idConvention->lookup()),
            $cipher,
            new EncryptedDataBuilder($idConvention->minter(), $cipherValueElement),
            new ReferenceListBuilder(),
            new ExternalPartSealer($cipher, new ExternalEncryptedDataBuilder($idConvention->minter())),
        );
    }

    public function __construct(
        private readonly TargetLocator $targetLocator,
        private readonly Cipher $cipher,
        private readonly EncryptedDataBuilder $encryptedDataBuilder,
        private readonly ReferenceListBuilder $referenceListBuilder,
        private readonly ExternalPartSealer $externalPartSealer,
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
            $sessionKey = $request->sessionKey;

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
                    $request->keyIdentifier,
                );
            }

            // Under the same session key, contributing to the same ReferenceList. The SwA profile wants one
            // key naming the in-document parts and the attachment parts together, and EncryptedKeyReader
            // refuses a second key in the container, so this cannot be a separate operation alongside the
            // first.
            $sealed = $request->externalParts === null
                ? new SealedExternalParts(ExternalPartList::of(), [])
                : $this->externalPartSealer->seal(
                    $document,
                    $container,
                    $request->externalParts,
                    $sessionKey,
                    $request->dataEncryptionMethod,
                    $request->keyIdentifier,
                );
            $partIds = [...$partIds, ...$sealed->ids];

            if ($partIds === []) {
                // The ReferenceList invariant, checked rather than assumed: every id in it came from work done
                // above, so an empty list here would name nothing while the message reads as encrypted. The
                // request guard makes this unreachable, and a static constraint is not a runtime check.
                throw EncryptionFailed::withReason('An encryption request must name at least one part.');
            }

            append($this->referenceListBuilder->build($document, $partIds))(
                $request->nestReferenceListIn ?? $container,
            );

            return new EncryptionResult($sealed->parts);
        } catch (EncryptionFailed $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw EncryptionFailed::withReason($exception->getMessage());
        }
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

            // An element whose content is a pointer cannot be encrypted: the ciphertext would cover the
            // reference while the bytes it names travel in the clear in their own MIME part, and the message
            // would still satisfy a policy check for that element being encrypted. Encrypting the part the
            // pointer names is the supported path, which is what external parts are for.
            if (XopInclude::hrefsIn($document, $element) !== []) {
                throw EncryptionFailed::withReason(
                    'An element carrying an xop:Include cannot be encrypted: that would protect the reference '
                    .'while the referenced bytes travel in the clear. Encrypt the attachment instead.',
                );
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
