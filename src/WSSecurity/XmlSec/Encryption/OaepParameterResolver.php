<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption;

use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\UnsupportedAlgorithmException;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\OaepHash;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\ElementText;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;

/**
 * Resolves the OAEP parameterization a xenc:EncryptionMethod declares into one KeyTransportAlgorithm.
 *
 * The OAEP digest and MGF children are read from the xenc:EncryptionMethod and mapped to a single OAEP hash:
 * the digest and MGF hashes must agree, the legacy rsa-oaep-mgf1p URI fixes SHA-1, and the resolved hash must
 * be on the profile allow-list. A non-empty xenc:OAEPparams (a non-empty label) is rejected. Every rejection
 * surfaces as the same UnsupportedAlgorithmException the caller folds into its uniform failure, so the
 * resolution carries no distinguishing detail and cannot become a Bleichenbacher oracle.
 */
final class OaepParameterResolver
{
    private const MGF1_SHA1 = 'http://www.w3.org/2009/xmlenc11#mgf1sha1';
    private const MGF1_SHA256 = 'http://www.w3.org/2009/xmlenc11#mgf1sha256';

    /**
     * @throws UnsupportedAlgorithmException
     */
    public function resolve(
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

            if ($child->localName === 'DigestMethod' && $child->namespaceURI === Namespaces::Ds->value) {
                $digestUri = (string) $child->getAttribute('Algorithm');
            }

            if ($child->localName === 'MGF' && $child->namespaceURI === Namespaces::Xenc11->value) {
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
        foreach (ChildElements::named($encryptionMethod, Namespaces::Xenc, 'OAEPparams') as $params) {
            if (ElementText::trimmed($params) !== '') {
                throw UnsupportedAlgorithmException::forAlgorithm('xenc:OAEPparams');
            }
        }
    }
}
