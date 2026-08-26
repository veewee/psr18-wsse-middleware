<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\OpenSSL\CipherText;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdMinter;
use Throwable;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Manipulator\append;
use function VeeWee\Xml\Dom\Manipulator\Node\replace_by_external_node;

/**
 * Serializes one encrypted Part as an xenc:EncryptedData element and replaces the original target node in the
 * document.
 *
 * For Content-mode Parts (soap:Body, wsu:Timestamp) the target element survives: its children are replaced by
 * the single xenc:EncryptedData. For Element-mode Parts the whole element is replaced by the xenc:EncryptedData.
 * The CipherValue carries IV || ciphertext [|| tag], base64 in the document unless a sink was given a
 * place to put the bytes instead; the injected IdMinter stamps an id on the
 * xenc:EncryptedData so the xenc:DataReference in the EncryptedKey can address it.
 */
final class EncryptedDataBuilder
{
    public function __construct(
        private readonly IdMinter $idMinter,
        private readonly CipherValueElement $cipherValueElement = new CipherValueElement(),
    ) {
    }

    /**
     * @return non-empty-string the id stamped on the xenc:EncryptedData, without the '#' fragment prefix, so
     *         the caller can emit a matching xenc:DataReference URI
     *
     * @throws EncryptionFailed
     */
    public function build(
        Document $document,
        Element $targetElement,
        CipherText $cipherText,
        DataEncryptionMethod $method,
        EncryptionMode $mode,
    ): string {
        try {
            $framed = $cipherText->iv.$cipherText->bytes.($cipherText->tag ?? '');
            $encryptedData = $this->buildEncryptedData($document, $framed, $method, $mode);
            $id = $this->idMinter->mint($encryptedData, $document);

            $this->place($targetElement, $encryptedData, $mode);

            return $id;
        } catch (EncryptionFailed $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw EncryptionFailed::withReason($exception->getMessage());
        }
    }

    private function buildEncryptedData(
        Document $document,
        string $framed,
        DataEncryptionMethod $method,
        EncryptionMode $mode,
    ): Element {
        return $document->map(namespaced_element(
            Namespaces::Xenc->value,
            Namespaces::Xenc->qualify('EncryptedData'),
            attribute('Type', $mode->value),
            children(
                static fn (): Element => $document->map(namespaced_element(
                    Namespaces::Xenc->value,
                    Namespaces::Xenc->qualify('EncryptionMethod'),
                    attribute('Algorithm', $method->value),
                )),
                fn (): Element => $document->map(namespaced_element(
                    Namespaces::Xenc->value,
                    Namespaces::Xenc->qualify('CipherData'),
                    children(
                        fn (): Element => $this->cipherValueElement->build($document, $framed),
                    ),
                )),
            ),
        ));
    }

    private function place(Element $targetElement, Element $encryptedData, EncryptionMode $mode): void
    {
        if ($mode === EncryptionMode::Element) {
            replace_by_external_node($targetElement, $encryptedData);

            return;
        }

        // Content mode: drop the element's existing children, then attach the single xenc:EncryptedData child.
        /** @var ?Node $child */
        $child = $targetElement->firstChild;
        while ($child !== null) {
            $targetElement->removeChild($child);
            /** @var ?Node $child */
            $child = $targetElement->firstChild;
        }

        append($encryptedData)($targetElement);
    }
}
