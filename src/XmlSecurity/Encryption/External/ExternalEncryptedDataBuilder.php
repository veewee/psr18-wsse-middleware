<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\OpenSSL\CipherText;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdMinter;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;
use Throwable;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;

/**
 * The sibling of EncryptedDataBuilder for a part whose bytes are not in the document: it emits an
 * xenc:EncryptedData carrying an xenc:CipherReference instead of an xenc:CipherValue.
 *
 * That is the whole difference, and it is what makes this a separate class rather than a mode on the other
 * one. A CipherValue builder must replace a node in the document; this one replaces nothing and returns a
 * detached element for the caller to place in the container, because there is no target node to stand in for.
 * The ciphertext itself never enters the XML.
 */
final class ExternalEncryptedDataBuilder
{
    public function __construct(
        private readonly IdMinter $idMinter,
    ) {
    }

    /**
     * @param non-empty-string $type      stamped as @Type, so a receiver knows which SwA mode produced this
     * @param non-empty-string $transform declared inside the CipherReference, so a receiver knows the
     *                                    referenced part holds ciphertext rather than the original bytes
     * @param ?KeyIdentifier   $keyIdentifier written as a ds:KeyInfo naming the key that encrypted the part
     *
     * @return array{0: Element, 1: non-empty-string} the detached element and the id stamped on it, so the
     *         caller can emit a matching xenc:DataReference and place the element itself
     *
     * @throws EncryptionFailed
     */
    public function build(
        Document $document,
        ExternalPart $part,
        CipherText $cipherText,
        DataEncryptionMethod $method,
        string $type,
        string $transform,
        ?KeyIdentifier $keyIdentifier = null,
    ): array {
        try {
            $cipherData = static fn (): Element => $document->map(namespaced_element(
                Namespaces::Xenc->value,
                Namespaces::Xenc->qualify('CipherData'),
                children(
                    static fn (): Element => $document->map(namespaced_element(
                        Namespaces::Xenc->value,
                        Namespaces::Xenc->qualify('CipherReference'),
                        // Verbatim. The engine neither parses nor rewrites a reference, which is what keeps it
                        // from needing to know that this one happens to be a cid.
                        attribute('URI', $part->reference),
                        children(
                            static fn (): Element => $document->map(namespaced_element(
                                Namespaces::Xenc->value,
                                Namespaces::Xenc->qualify('Transforms'),
                                children(
                                    static fn (): Element => $document->map(namespaced_element(
                                        Namespaces::Ds->value,
                                        Namespaces::Ds->qualify('Transform'),
                                        attribute('Algorithm', $transform),
                                    )),
                                ),
                            )),
                        ),
                    )),
                ),
            ));

            $encryptionMethod = static fn (): Element => $document->map(namespaced_element(
                Namespaces::Xenc->value,
                Namespaces::Xenc->qualify('EncryptionMethod'),
                attribute('Algorithm', $method->value),
            ));

            // Schema order: EncryptionMethod, then ds:KeyInfo, then CipherData.
            $keyInfo = $keyIdentifier?->apply($document);
            $childBuilders = $keyInfo === null
                ? [$encryptionMethod, $cipherData]
                : [$encryptionMethod, static fn (): Element => $keyInfo, $cipherData];

            $encryptedData = $document->map(namespaced_element(
                Namespaces::Xenc->value,
                Namespaces::Xenc->qualify('EncryptedData'),
                attribute('Type', $type),
                // The part's own media type, so a receiver can restore it after decrypting. The part on the
                // wire will be labelled opaque, since its bytes are no longer of that type.
                attribute('MimeType', $part->mimeType),
                children(...$childBuilders),
            ));

            return [$encryptedData, $this->idMinter->mint($encryptedData, $document)];
        } catch (EncryptionFailed $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw EncryptionFailed::withReason($exception->getMessage());
        }
    }
}
