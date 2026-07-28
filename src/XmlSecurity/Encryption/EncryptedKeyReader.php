<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\Algorithm\Exception\UnsupportedAlgorithmException;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\Query;
use Soap\Psr18WsseMiddleware\Xml\SameDocumentId;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\DecryptionFailed;
use Throwable;
use VeeWee\Xml\Dom\Document;

/**
 * Locates the single xenc:EncryptedKey in the container the caller names, extracts the wrapped key bytes from
 * the CipherValue, and unwraps the session key through OpenSSL\KeyTransport. The OAEP parameterization the
 * xenc:EncryptionMethod declares is resolved and allow-list checked by OaepParameterResolver before any unwrap.
 *
 * The container bounds every lookup here. A document-wide search would make any xenc:EncryptedKey in the message
 * a candidate, and since our public key is public an injected one would be unwrapped with our private key,
 * letting a session key of the attacker's choosing decide what the plaintext becomes.
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
        Element $container,
        #[SensitiveParameter] Key $privateKey,
        ?CryptoPolicy $policy = null,
    ): SessionKey {
        $policy ??= CryptoPolicy::default();

        try {
            $encryptedKey = $this->locate($document, $container);
            $encryptionMethod = $this->child($encryptedKey, 'EncryptionMethod', Namespaces::Xenc);

            $method = $this->keyEncryptionMethod($encryptionMethod);

            // The OAEP parameterization is resolved and allow-list checked here, before any unwrap, and folded
            // into the one uniform failure so it cannot be told apart from a key-unwrap error.
            $algorithm = $this->oaepParameterResolver->resolve($method, $encryptionMethod, $policy);

            $wrappedKey = $this->wrappedKey($encryptedKey);
            $sessionKey = $this->keyTransport->unwrap($wrappedKey, $privateKey, $algorithm);
        } catch (DecryptionFailed $exception) {
            throw $exception;
        } catch (UnsupportedAlgorithmException | CryptoOperationFailed | Throwable $exception) {
            throw DecryptionFailed::withReason('Unable to unwrap the session key.');
        }

        return $sessionKey;
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
     * Counts the xenc:DataReference entries the message declares. The caller enforces the part-count cap with
     * this number before any unwrap or decrypt work.
     *
     * @return list<non-empty-string> the bare ids (without the '#' prefix) each DataReference URI points at
     *
     * @throws DecryptionFailed
     */
    public function dataReferences(Document $document, Element $container): array
    {
        $referenceList = $this->referenceList($document, $container);

        $ids = [];
        foreach (ChildElements::named($referenceList, Namespaces::Xenc, 'DataReference') as $child) {
            $ids[] = SameDocumentId::parse((string) $child->getAttribute('URI'))
                ?? throw DecryptionFailed::withReason(
                    'A data reference URI must be a non-empty same-document id.',
                );
        }

        if ($ids === []) {
            throw DecryptionFailed::withReason('The reference list declares no data references.');
        }

        return $ids;
    }

    /**
     * The one xenc:ReferenceList naming the encrypted parts. XML-Enc lets it sit inside the xenc:EncryptedKey
     * or stand detached beside it in the container, and peers emit both shapes, so either is accepted —
     * but never both at once and never two of one form. This list decides which parts the decryptor touches,
     * so a second candidate is refused outright instead of one being chosen: picking either would let the
     * other be injected. A duplicate of one form is refused rather than read as an absence, which would
     * otherwise let it fall through to an injected instance of the other form.
     *
     * The detached form is looked for as a child of the container only. Searched document-wide it would let a
     * list planted elsewhere name the parts, which decides what the session key is applied to.
     *
     * @throws DecryptionFailed
     */
    private function referenceList(Document $document, Element $container): Element
    {
        $carried = ChildElements::named($this->locate($document, $container), Namespaces::Xenc, 'ReferenceList');
        $detached = Query::elements(
            $document,
            './'.Namespaces::Xenc->qualify('ReferenceList'),
            $container,
        )->map(static fn (Element $element): Element => $element);

        if (count($carried) > 1 || count($detached) > 1 || (count($carried) === 1 && count($detached) === 1)) {
            throw DecryptionFailed::withReason('Exactly one xenc:ReferenceList is required.');
        }

        return $carried[0]
            ?? $detached[0]
            ?? throw DecryptionFailed::withReason('Exactly one xenc:ReferenceList is required.');
    }

    /**
     * @throws DecryptionFailed
     */
    private function wrappedKey(Element $encryptedKey): string
    {
        $cipherData = $this->child($encryptedKey, 'CipherData', Namespaces::Xenc);
        $cipherValue = $this->child($cipherData, 'CipherValue', Namespaces::Xenc);

        $decoded = base64_decode(ElementText::trimmed($cipherValue), true);
        if ($decoded === false || $decoded === '') {
            throw DecryptionFailed::withReason('The wrapped key is not valid base64.');
        }

        return $decoded;
    }

    /**
     * @throws DecryptionFailed
     */
    private function locate(Document $document, Element $container): Element
    {
        $encryptedKeys = Query::elements(
            $document,
            './'.Namespaces::Xenc->qualify('EncryptedKey'),
            $container,
        );

        if ($encryptedKeys->count() !== 1) {
            throw DecryptionFailed::withReason('Exactly one xenc:EncryptedKey is required in the container.');
        }

        return $encryptedKeys->expectSingle();
    }

    /**
     * @throws DecryptionFailed
     */
    private function child(Element $parent, string $localName, Namespaces $namespace): Element
    {
        // Exactly one, so an injected sibling cannot shadow the element the unwrap depends on.
        return ChildElements::single($parent, $namespace, $localName)
            ?? throw DecryptionFailed::withReason(sprintf('%s is missing.', $localName));
    }
}
