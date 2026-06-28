<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption;

use Dom\Element;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\UnsupportedAlgorithmException;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\DecryptionFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Xpath;
use Throwable;
use VeeWee\Xml\Dom\Document;

/**
 * Locates the single xenc:EncryptedKey in the wsse:Security header, extracts the wrapped key bytes from the
 * CipherValue, and unwraps the session key through OpenSSL\KeyTransport. The OAEP parameterization the
 * xenc:EncryptionMethod declares is resolved and allow-list checked by OaepParameterResolver before any unwrap.
 *
 * Every structural rejection, every disallowed parameterization, and every unwrap failure collapse to one
 * uniform DecryptionFailed, so the reader is never a Bleichenbacher oracle.
 */
final class EncryptedKeyReader
{
    private readonly OaepParameterResolver $oaepParameterResolver;

    public function __construct(
        private readonly KeyTransport $keyTransport,
    ) {
        $this->oaepParameterResolver = new OaepParameterResolver();
    }

    /**
     * @throws DecryptionFailed
     */
    public function read(
        Document $document,
        #[SensitiveParameter] Key $privateKey,
        ?SecurityProfile $profile = null,
    ): UnwrappedKey {
        $profile ??= SecurityProfile::default();

        try {
            $encryptedKey = $this->locate($document);
            $encryptionMethod = $this->child($encryptedKey, 'EncryptionMethod', Namespaces::Xenc);

            $method = $this->keyEncryptionMethod($encryptionMethod);

            // The OAEP parameterization is resolved and allow-list checked here, before any unwrap, and folded
            // into the one uniform failure so it cannot be told apart from a key-unwrap error.
            $algorithm = $this->oaepParameterResolver->resolve($method, $encryptionMethod, $profile);

            $wrappedKey = $this->wrappedKey($encryptedKey);
            $sessionKey = $this->keyTransport->unwrap($wrappedKey, $privateKey, $algorithm);
        } catch (DecryptionFailed $exception) {
            throw $exception;
        } catch (UnsupportedAlgorithmException | CryptoOperationFailed | Throwable $exception) {
            throw DecryptionFailed::withReason('Unable to unwrap the session key.');
        }

        return new UnwrappedKey($sessionKey);
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
        $referenceList = $this->child($encryptedKey, 'ReferenceList', Namespaces::Xenc);

        $ids = [];
        foreach (ChildElements::named($referenceList, Namespaces::Xenc, 'DataReference') as $child) {
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

    /**
     * @throws DecryptionFailed
     */
    private function wrappedKey(Element $encryptedKey): string
    {
        $cipherData = $this->child($encryptedKey, 'CipherData', Namespaces::Xenc);
        $cipherValue = $this->child($cipherData, 'CipherValue', Namespaces::Xenc);

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
            ->xpath(new Xpath($document))
            ->query(
                '//'.Namespaces::Wsse->qualify('Security').'/'.Namespaces::Xenc->qualify('EncryptedKey'),
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
    private function child(Element $parent, string $localName, Namespaces $namespace): Element
    {
        // Exactly one, so an injected sibling cannot shadow the element the unwrap depends on.
        $matches = ChildElements::named($parent, $namespace, $localName);
        if (count($matches) !== 1) {
            throw DecryptionFailed::withReason(sprintf('%s is missing.', $localName));
        }

        return $matches[0];
    }
}
