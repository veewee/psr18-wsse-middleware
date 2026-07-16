<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * Assembles a ds:SignedInfo element with ds:CanonicalizationMethod, ds:SignatureMethod, and one ds:Reference
 * per DigestResult. The returned element is detached; the caller attaches it as a child of ds:Signature.
 *
 * Each ds:Reference declares the C14N transform it was digested with, so a verifier canonicalizes the
 * referenced element the same way before checking the digest. The same canonicalization drives both the
 * SignedInfo method and every reference transform.
 */
final class SignedInfoBuilder
{
    /**
     * @param non-empty-list<DigestResult> $references
     */
    public function build(
        Document $document,
        SignatureCanonicalization $canonicalization,
        SignatureMethod $signatureMethod,
        array $references,
    ): Element {
        $referenceBuilders = array_map(
            fn (DigestResult $result): callable => $this->reference($result, $canonicalization),
            $references,
        );

        return $document->map(namespaced_element(
            Namespaces::Ds->value,
            Namespaces::Ds->qualify('SignedInfo'),
            children(
                namespaced_element(
                    Namespaces::Ds->value,
                    Namespaces::Ds->qualify('CanonicalizationMethod'),
                    attribute('Algorithm', $canonicalization->value),
                ),
                namespaced_element(
                    Namespaces::Ds->value,
                    Namespaces::Ds->qualify('SignatureMethod'),
                    attribute('Algorithm', $signatureMethod->value),
                ),
                ...$referenceBuilders,
            ),
        ));
    }

    /**
     * @return callable(Element): Element
     */
    private function reference(DigestResult $result, SignatureCanonicalization $canonicalization): callable
    {
        return namespaced_element(
            Namespaces::Ds->value,
            Namespaces::Ds->qualify('Reference'),
            attribute('URI', '#'.$result->wsuId),
            children(
                namespaced_element(
                    Namespaces::Ds->value,
                    Namespaces::Ds->qualify('Transforms'),
                    children(namespaced_element(
                        Namespaces::Ds->value,
                        Namespaces::Ds->qualify('Transform'),
                        attribute('Algorithm', $canonicalization->value),
                    )),
                ),
                namespaced_element(
                    Namespaces::Ds->value,
                    Namespaces::Ds->qualify('DigestMethod'),
                    attribute('Algorithm', $result->digestMethod->value),
                ),
                namespaced_element(
                    Namespaces::Ds->value,
                    Namespaces::Ds->qualify('DigestValue'),
                    value($result->digestValueBase64),
                ),
            ),
        );
    }
}
