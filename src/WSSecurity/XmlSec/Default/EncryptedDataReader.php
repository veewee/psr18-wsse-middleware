<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default;

use Dom\Element;
use Dom\Node;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\CipherText;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\DecryptionFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Throwable;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Manipulator\Node\append_external_node;
use function VeeWee\Xml\Dom\Manipulator\Node\replace_by_external_node;

/**
 * Decrypts one xenc:EncryptedData element and replaces it in the document with the recovered plaintext.
 *
 * It reads the per-element xenc:EncryptionMethod, base64-decodes the CipherValue, splits the framed
 * IV || ciphertext [|| tag] for that method, decrypts through OpenSSL\Cipher, and reconstructs the DOM:
 * Element mode replaces the xenc:EncryptedData itself, Content mode replaces its parent's children. Every
 * cipher, structural, or parse failure collapses to one uniform DecryptionFailed so the reader cannot become
 * a padding or tag-validity oracle.
 */
final class EncryptedDataReader
{
    private const int GCM_TAG_LENGTH = 16;

    public function __construct(
        private readonly Cipher $cipher,
    ) {
    }

    /**
     * @throws DecryptionFailed
     */
    public function read(
        Document $document,
        Element $encryptedDataElement,
        #[SensitiveParameter] string $sessionKey,
    ): void {
        try {
            $method = $this->method($encryptedDataElement);
            $cipherText = $this->frame($encryptedDataElement, $method);

            $plaintext = $this->cipher->decrypt($cipherText, $sessionKey, $method);

            $this->restore($document, $encryptedDataElement, $plaintext);
        } catch (DecryptionFailed $exception) {
            throw $exception;
        } catch (CryptoOperationFailed | Throwable $exception) {
            // Uniform: a cipher failure, a missing tag, a parse failure and a structural error are
            // indistinguishable to the caller, so the reader is never an oracle.
            throw DecryptionFailed::withReason('Unable to decrypt an encrypted element.');
        }
    }

    private function method(Element $encryptedDataElement): DataEncryptionMethod
    {
        $encryptionMethod = $this->child($encryptedDataElement, 'EncryptionMethod');
        $algorithm = DataEncryptionMethod::tryFrom((string) $encryptionMethod->getAttribute('Algorithm'));

        return $algorithm
            ?? throw DecryptionFailed::withReason('The data-encryption method is unknown.');
    }

    private function frame(Element $encryptedDataElement, DataEncryptionMethod $method): CipherText
    {
        $cipherData = $this->child($encryptedDataElement, 'CipherData');
        $cipherValue = $this->child($cipherData, 'CipherValue');

        $decoded = base64_decode(trim((string) $cipherValue->textContent), true);
        if ($decoded === false) {
            throw DecryptionFailed::withReason('The cipher value is not valid base64.');
        }

        $ivLength = $this->ivLength($method);
        $tagLength = $method->isGcm() ? self::GCM_TAG_LENGTH : 0;

        if (strlen($decoded) < $ivLength + $tagLength) {
            throw DecryptionFailed::withReason('The framed cipher value is too short for the declared method.');
        }

        $iv = substr($decoded, 0, $ivLength);
        if ($tagLength > 0) {
            $tag = substr($decoded, -$tagLength);
            $bytes = substr($decoded, $ivLength, strlen($decoded) - $ivLength - $tagLength);

            return new CipherText($iv, $bytes, $tag);
        }

        return new CipherText($iv, substr($decoded, $ivLength), null);
    }

    private function restore(Document $document, Element $encryptedDataElement, string $plaintext): void
    {
        $mode = EncryptionMode::tryFrom((string) $encryptedDataElement->getAttribute('Type'))
            ?? EncryptionMode::Element;

        $recovered = $this->parseFragment($plaintext);

        if ($mode === EncryptionMode::Element) {
            $first = $recovered[0] ?? throw DecryptionFailed::withReason('The recovered element is empty.');
            replace_by_external_node($encryptedDataElement, $first);

            return;
        }

        $parent = $encryptedDataElement->parentNode;
        if (!$parent instanceof Element) {
            throw DecryptionFailed::withReason('The encrypted content has no parent element to restore into.');
        }

        $parent->removeChild($encryptedDataElement);
        foreach ($recovered as $node) {
            append_external_node($parent, $node);
        }
    }

    /**
     * @return list<Node>
     */
    private function parseFragment(string $plaintext): array
    {
        // Wrapping lets a Content-mode payload of several siblings (or mixed text) parse as one document; the
        // wrapper carries no namespace, so the recovered nodes keep the declarations they were serialized with.
        $fragment = Document::fromXmlString('<fragment>'.$plaintext.'</fragment>');

        $nodes = [];
        /** @var Node $node */
        foreach ($fragment->locateDocumentElement()->childNodes as $node) {
            $nodes[] = $node;
        }

        return $nodes;
    }

    private function child(Element $parent, string $localName): Element
    {
        /** @var Node $child */
        foreach ($parent->childNodes as $child) {
            if ($child instanceof Element
                && $child->localName === $localName
                && $child->namespaceURI === WsseNamespace::Xenc->value
            ) {
                return $child;
            }
        }

        throw DecryptionFailed::withReason(sprintf('xenc:%s is missing.', $localName));
    }

    /**
     * @return positive-int
     */
    private function ivLength(DataEncryptionMethod $method): int
    {
        return match ($method) {
            DataEncryptionMethod::TRIPLEDES_CBC => 8,
            DataEncryptionMethod::AES128_CBC,
            DataEncryptionMethod::AES192_CBC,
            DataEncryptionMethod::AES256_CBC => 16,
            DataEncryptionMethod::AES128_GCM,
            DataEncryptionMethod::AES192_GCM,
            DataEncryptionMethod::AES256_GCM => 12,
        };
    }
}
