<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption;

use Dom\Element;
use Dom\Node;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\UnsupportedAlgorithmException;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\OaepHash;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\DecryptionFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseXpath;
use Throwable;
use VeeWee\Xml\Dom\Document;

/**
 * Locates the single xenc:EncryptedKey in the wsse:Security header, resolves the OAEP parameterization it
 * declares (SHA-1 or SHA-256, both accepted), extracts the wrapped key bytes from the CipherValue, and unwraps
 * the session key through OpenSSL\KeyTransport.
 *
 * The OAEP digest and MGF children are read from the xenc:EncryptionMethod and mapped to a single OAEP hash:
 * the digest and MGF hashes must agree, the legacy rsa-oaep-mgf1p URI fixes SHA-1, and the resolved hash must
 * be on the profile allow-list. A non-empty xenc:OAEPparams (a non-empty label) is rejected. Every structural
 * rejection and every unwrap failure collapse to one uniform DecryptionFailed, so the reader is never a
 * Bleichenbacher oracle.
 */
final class EncryptedKeyReader
{
    private const MGF1_SHA1 = 'http://www.w3.org/2009/xmlenc11#mgf1sha1';
    private const MGF1_SHA256 = 'http://www.w3.org/2009/xmlenc11#mgf1sha256';

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
        ?SecurityProfile $profile = null,
    ): UnwrappedKey {
        $profile ??= SecurityProfile::default();

        try {
            $encryptedKey = $this->locate($document);
            $encryptionMethod = $this->child($encryptedKey, 'EncryptionMethod', WsseNamespace::Xenc);

            $method = $this->keyEncryptionMethod($encryptionMethod);

            // The OAEP parameterization is resolved and allow-list checked here, before any unwrap, and folded
            // into the one uniform failure so it cannot be told apart from a key-unwrap error.
            $algorithm = $this->resolveAlgorithm($method, $encryptionMethod, $profile);

            $wrappedKey = $this->wrappedKey($encryptedKey);
            $sessionKey = $this->keyTransport->unwrap($wrappedKey, $privateKey, $algorithm);
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
        $referenceList = $this->child($encryptedKey, 'ReferenceList', WsseNamespace::Xenc);

        $ids = [];
        foreach (ChildElements::named($referenceList, WsseNamespace::Xenc, 'DataReference') as $child) {
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
     * @throws UnsupportedAlgorithmException
     */
    private function resolveAlgorithm(
        KeyEncryptionMethod $method,
        Element $encryptionMethod,
        SecurityProfile $profile,
    ): KeyTransportAlgorithm {
        if ($method === KeyEncryptionMethod::RSA_1_5) {
            return KeyTransportAlgorithm::rsa1_5();
        }

        $oaepHash = $this->resolveOaepHash($method, $encryptionMethod);

        if (!$profile->acceptsOaepHash($oaepHash)) {
            throw UnsupportedAlgorithmException::forAlgorithm($oaepHash->digestMethod()->value);
        }

        return KeyTransportAlgorithm::fromMethod($method, $oaepHash);
    }

    /**
     * Maps the declared DigestMethod / MGF children onto one OAEP hash, defaulting absent children to SHA-1 /
     * MGF1-SHA1 per the spec, and requiring the digest and MGF hashes to agree. The legacy rsa-oaep-mgf1p URI
     * fixes MGF1-SHA1, so it admits no MGF child and no non-SHA-1 digest. A non-empty OAEPparams is rejected.
     *
     * @throws UnsupportedAlgorithmException
     */
    private function resolveOaepHash(KeyEncryptionMethod $method, Element $encryptionMethod): OaepHash
    {
        $this->rejectNonEmptyOaepParams($encryptionMethod);

        $digestUri = null;
        $mgfUri = null;

        /** @var Node $child */
        foreach ($encryptionMethod->childNodes as $child) {
            if (!$child instanceof Element) {
                continue;
            }

            if ($child->localName === 'DigestMethod' && $child->namespaceURI === WsseNamespace::Ds->value) {
                $digestUri = (string) $child->getAttribute('Algorithm');
            }

            if ($child->localName === 'MGF' && $child->namespaceURI === WsseNamespace::Xenc11->value) {
                $mgfUri = (string) $child->getAttribute('Algorithm');
            }
        }

        $digestHash = $digestUri === null || $digestUri === ''
            ? OaepHash::Sha1
            : OaepHash::fromDigest($this->digest($digestUri));

        $mgfHash = $this->mgfHash($mgfUri);

        // The MGF hash must match the OAEP digest hash; a mismatched pair is rejected.
        if ($mgfHash !== $digestHash) {
            throw UnsupportedAlgorithmException::forAlgorithm($mgfUri ?? '');
        }

        // The legacy URI fixes MGF1-SHA1, so it carries no MGF child and no non-SHA-1 digest.
        if ($method === KeyEncryptionMethod::RSA_OAEP_MGF1P) {
            if ($mgfUri !== null || $digestHash !== OaepHash::Sha1) {
                throw UnsupportedAlgorithmException::forAlgorithm($digestUri ?? $mgfUri ?? '');
            }
        }

        return $digestHash;
    }

    /**
     * @throws UnsupportedAlgorithmException
     */
    private function digest(string $uri): DigestMethod
    {
        return DigestMethod::tryFrom($uri)
            ?? throw UnsupportedAlgorithmException::forAlgorithm($uri);
    }

    /**
     * @throws UnsupportedAlgorithmException
     */
    private function mgfHash(?string $uri): OaepHash
    {
        return match ($uri) {
            null, '', self::MGF1_SHA1 => OaepHash::Sha1,
            self::MGF1_SHA256 => OaepHash::Sha256,
            default => throw UnsupportedAlgorithmException::forAlgorithm($uri),
        };
    }

    /**
     * @throws UnsupportedAlgorithmException
     */
    private function rejectNonEmptyOaepParams(Element $encryptionMethod): void
    {
        // We assume the empty label L="". A non-empty OAEPparams declares a label we do not support.
        foreach (ChildElements::named($encryptionMethod, WsseNamespace::Xenc, 'OAEPparams') as $params) {
            if (trim((string) $params->textContent) !== '') {
                throw UnsupportedAlgorithmException::forAlgorithm('xenc:OAEPparams');
            }
        }
    }

    /**
     * @throws DecryptionFailed
     */
    private function wrappedKey(Element $encryptedKey): string
    {
        $cipherData = $this->child($encryptedKey, 'CipherData', WsseNamespace::Xenc);
        $cipherValue = $this->child($cipherData, 'CipherValue', WsseNamespace::Xenc);

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
    private function child(Element $parent, string $localName, WsseNamespace $namespace): Element
    {
        // Exactly one, so an injected sibling cannot shadow the element the unwrap depends on.
        $matches = ChildElements::named($parent, $namespace, $localName);
        if (count($matches) !== 1) {
            throw DecryptionFailed::withReason(sprintf('%s is missing.', $localName));
        }

        return $matches[0];
    }
}
