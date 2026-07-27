<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\Exception\UnsupportedAlgorithmException;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\Algorithm\OaepHash;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\ElementName;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;

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
    /**
     * @throws UnsupportedAlgorithmException
     */
    public function resolve(
        KeyEncryptionMethod $method,
        Element $encryptionMethod,
        CryptoPolicy $policy,
    ): KeyTransportAlgorithm {
        if ($method === KeyEncryptionMethod::RSA_1_5) {
            return KeyTransportAlgorithm::rsa1_5();
        }

        $oaepHash = $this->resolveOaepHash($method, $encryptionMethod);

        if (!$policy->acceptsOaepHash($oaepHash)) {
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

            if (ElementName::matches($child, Namespaces::Ds, 'DigestMethod')) {
                $digestUri = (string) $child->getAttribute('Algorithm');
            }

            if (ElementName::matches($child, Namespaces::Xenc11, 'MGF')) {
                $mgfUri = (string) $child->getAttribute('Algorithm');
            }
        }

        $digestHash = $digestUri === null || $digestUri === ''
            ? OaepHash::Sha1
            : OaepHash::fromDigest($this->digest($digestUri));

        $mgfHash = OaepHash::fromMgfUri($mgfUri);

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
