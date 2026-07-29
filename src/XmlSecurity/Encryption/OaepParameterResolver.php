<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\Exception\UnsupportedAlgorithmException;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\Algorithm\OaepHash;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\XmlNamespace;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;

/**
 * Resolves the OAEP parameterization a xenc:EncryptionMethod declares into one KeyTransportAlgorithm.
 *
 * The OAEP digest and MGF children are read from the xenc:EncryptionMethod and mapped to a label hash: under
 * rsa-oaep the declared digest and MGF hashes must agree, while the legacy rsa-oaep-mgf1p URI fixes the mask to
 * MGF1-SHA1 and so declares no MGF child while leaving the label digest free. The resolved hash must be on the
 * profile allow-list. A non-empty xenc:OAEPparams (a non-empty label) is rejected. Every rejection
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
        // The allow-list is consulted before the method branches: rsa-1_5 carries no OAEP parameters to
        // resolve, so its short-circuit would otherwise return an algorithm the policy never admitted.
        if (!$policy->acceptsKeyEncryptionMethod($method)) {
            throw UnsupportedAlgorithmException::forAlgorithm($method->value);
        }

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
     * Maps the declared DigestMethod / MGF children onto the OAEP label hash, defaulting an absent digest to
     * SHA-1 per the spec. A non-empty OAEPparams is rejected.
     *
     * @throws UnsupportedAlgorithmException
     */
    private function resolveOaepHash(KeyEncryptionMethod $method, Element $encryptionMethod): OaepHash
    {
        $this->rejectNonEmptyOaepParams($encryptionMethod);

        $digestUri = $this->declaredAlgorithm($encryptionMethod, Namespaces::Ds, 'DigestMethod');
        $mgfUri = $this->declaredAlgorithm($encryptionMethod, Namespaces::Xenc11, 'MGF');

        $digestHash = $digestUri === null || $digestUri === ''
            ? OaepHash::Sha1
            : OaepHash::fromDigest($this->digest($digestUri));

        // The legacy URI fixes the mask to MGF1-SHA1, so it declares no MGF child at all. The label digest
        // stays free of that: a SHA-256 digest under this URI means a SHA-256 label with a SHA-1 mask, which
        // is what a conforming peer emits and what the resolved algorithm carries.
        if ($method === KeyEncryptionMethod::RSA_OAEP_MGF1P) {
            if ($mgfUri !== null) {
                throw UnsupportedAlgorithmException::forAlgorithm($mgfUri);
            }

            return $digestHash;
        }

        // Under rsa-oaep both are declarable, and the pair is required to agree: a mismatch is not something a
        // peer needs and admitting it would only widen the parameterizations that reach the unwrap.
        if (OaepHash::fromMgfUri($mgfUri) !== $digestHash) {
            throw UnsupportedAlgorithmException::forAlgorithm($mgfUri ?? '');
        }

        return $digestHash;
    }

    /**
     * Reads the Algorithm of an at-most-once child, or null when it is absent. A second child is refused
     * rather than resolved to one of them: it would otherwise decide the parameterization the unwrap runs
     * under, which is the shape every other duplicate child in this codebase is refused for.
     *
     * @throws UnsupportedAlgorithmException
     */
    private function declaredAlgorithm(Element $encryptionMethod, XmlNamespace $namespace, string $localName): ?string
    {
        $matches = ChildElements::named($encryptionMethod, $namespace, $localName);
        if (count($matches) > 1) {
            throw UnsupportedAlgorithmException::forAlgorithm($namespace->qualify($localName));
        }

        $declared = $matches[0] ?? null;

        return $declared === null ? null : (string) $declared->getAttribute('Algorithm');
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
