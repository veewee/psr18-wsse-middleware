<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default;

use Dom\Element;
use Dom\Node;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\UnsupportedAlgorithmException;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\DecryptionFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseXpath;
use Throwable;
use VeeWee\Xml\Dom\Document;

/**
 * Locates the single xenc:EncryptedKey in the wsse:Security header, refuses a non-SHA-1 OAEP parameterization
 * before any unwrap attempt, extracts the wrapped key bytes from the CipherValue, and unwraps the session key
 * through OpenSSL\KeyTransport.
 *
 * The high-level openssl OAEP API is SHA-1 / MGF1-SHA1 only. When the xenc:EncryptionMethod declares a
 * DigestMethod or MGF child whose Algorithm is not SHA-1, this reader throws rather than silently computing
 * SHA-1 against a SHA-256 declaration. Every unwrap failure (CryptoOperationFailed) and every structural
 * failure collapse to one uniform DecryptionFailed, so the reader is never a Bleichenbacher oracle.
 */
final class EncryptedKeyReader
{
    private const SHA1_DIGEST = 'http://www.w3.org/2000/09/xmldsig#sha1';
    private const MGF1_SHA1 = 'http://www.w3.org/2009/xmlenc11#mgf1sha1';
    private const XENC11_NS = 'http://www.w3.org/2009/xmlenc11#';

    public function __construct(
        private readonly KeyTransport $keyTransport,
    ) {
    }

    /**
     * @throws DecryptionFailed
     */
    public function read(
        Document $document,
        #[SensitiveParameter] Key $privateKey,
    ): UnwrappedKey {
        try {
            $encryptedKey = $this->locate($document);
            $encryptionMethod = $this->child($encryptedKey, 'EncryptionMethod', WsseNamespace::Xenc->value);

            $method = $this->keyEncryptionMethod($encryptionMethod);

            // A non-SHA-1 OAEP parameterization is refused here, before any unwrap, and is folded into the one
            // uniform failure so it cannot be told apart from a key-unwrap error.
            $this->refuseNonSha1Oaep($encryptionMethod);

            $wrappedKey = $this->wrappedKey($encryptedKey);
            $sessionKey = $this->keyTransport->unwrap($wrappedKey, $privateKey, $method);
        } catch (DecryptionFailed $exception) {
            throw $exception;
        } catch (UnsupportedAlgorithmException | CryptoOperationFailed | Throwable $exception) {
            throw DecryptionFailed::withReason('Unable to unwrap the session key.');
        }

        return new UnwrappedKey($sessionKey, DataEncryptionMethod::default());
    }

    /**
     * @throws DecryptionFailed
     */
    private function keyEncryptionMethod(Element $encryptionMethod): KeyEncryptionMethod
    {
        $algorithm = KeyEncryptionMethod::tryFrom((string) $encryptionMethod->getAttribute('Algorithm'));

        return $algorithm
            ?? throw DecryptionFailed::withReason('The key-encryption method is unknown.');
    }

    /**
     * Counts the xenc:DataReference entries declared inside the xenc:EncryptedKey's xenc:ReferenceList. The
     * caller enforces the part-count cap with this number before any unwrap or decrypt work.
     *
     * @return list<string> the bare ids (without the '#' prefix) each DataReference URI points at
     *
     * @throws DecryptionFailed
     */
    public function dataReferences(Document $document): array
    {
        $encryptedKey = $this->locate($document);
        $referenceList = $this->child($encryptedKey, 'ReferenceList', WsseNamespace::Xenc->value);

        $ids = [];
        /** @var Node $child */
        foreach ($referenceList->childNodes as $child) {
            if (!$child instanceof Element
                || $child->localName !== 'DataReference'
                || $child->namespaceURI !== WsseNamespace::Xenc->value
            ) {
                continue;
            }

            $uri = (string) $child->getAttribute('URI');
            if (!str_starts_with($uri, '#') || $uri === '#') {
                throw DecryptionFailed::withReason('A data reference URI must be a non-empty same-document id.');
            }

            $ids[] = substr($uri, 1);
        }

        if ($ids === []) {
            throw DecryptionFailed::withReason('The reference list declares no data references.');
        }

        return $ids;
    }

    private function refuseNonSha1Oaep(Element $encryptionMethod): void
    {
        /** @var Node $child */
        foreach ($encryptionMethod->childNodes as $child) {
            if (!$child instanceof Element) {
                continue;
            }

            if ($child->localName === 'DigestMethod' && $child->namespaceURI === WsseNamespace::Ds->value) {
                $algorithm = (string) $child->getAttribute('Algorithm');
                if ($algorithm !== '' && $algorithm !== self::SHA1_DIGEST) {
                    throw UnsupportedAlgorithmException::forAlgorithm($algorithm);
                }
            }

            if ($child->localName === 'MGF' && $child->namespaceURI === self::XENC11_NS) {
                $algorithm = (string) $child->getAttribute('Algorithm');
                if ($algorithm !== '' && $algorithm !== self::MGF1_SHA1) {
                    throw UnsupportedAlgorithmException::forAlgorithm($algorithm);
                }
            }
        }
    }

    /**
     * @throws DecryptionFailed
     */
    private function wrappedKey(Element $encryptedKey): string
    {
        $cipherData = $this->child($encryptedKey, 'CipherData', WsseNamespace::Xenc->value);
        $cipherValue = $this->child($cipherData, 'CipherValue', WsseNamespace::Xenc->value);

        $decoded = base64_decode(trim((string) $cipherValue->textContent), true);
        if ($decoded === false || $decoded === '') {
            throw DecryptionFailed::withReason('The wrapped key is not valid base64.');
        }

        return $decoded;
    }

    /**
     * @throws DecryptionFailed
     */
    private function locate(Document $document): Element
    {
        $encryptedKeys = $document
            ->xpath(new WsseXpath($document))
            ->query(
                '//'.WsseNamespace::Wsse->qualify('Security').'/'.WsseNamespace::Xenc->qualify('EncryptedKey'),
            )
            ->expectAllOfType(Element::class);

        if ($encryptedKeys->count() !== 1) {
            throw DecryptionFailed::withReason('Exactly one xenc:EncryptedKey is required in the Security header.');
        }

        return $encryptedKeys->expectSingle();
    }

    /**
     * @throws DecryptionFailed
     */
    private function child(Element $parent, string $localName, string $namespace): Element
    {
        /** @var Node $child */
        foreach ($parent->childNodes as $child) {
            if ($child instanceof Element && $child->localName === $localName && $child->namespaceURI === $namespace) {
                return $child;
            }
        }

        throw DecryptionFailed::withReason(sprintf('%s is missing.', $localName));
    }
}
