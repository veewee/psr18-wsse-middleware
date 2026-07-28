<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
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
     * @param list<string>                 $inclusivePrefixes the PrefixList ds:SignedInfo itself is canonicalized under
     */
    public function build(
        Document $document,
        SignatureCanonicalization $canonicalization,
        SignatureMethod $signatureMethod,
        array $references,
        array $inclusivePrefixes = [],
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
                    ...$this->inclusiveNamespaces($canonicalization, $inclusivePrefixes),
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
            attribute('URI', '#'.$result->id),
            children(
                namespaced_element(
                    Namespaces::Ds->value,
                    Namespaces::Ds->qualify('Transforms'),
                    children(namespaced_element(
                        Namespaces::Ds->value,
                        Namespaces::Ds->qualify('Transform'),
                        attribute('Algorithm', $canonicalization->value),
                        ...$this->inclusiveNamespaces($canonicalization, $result->inclusivePrefixes),
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

    /**
     * The ec:InclusiveNamespaces child pinning a PrefixList, or nothing at all. A PrefixList parameterizes
     * exclusive C14N only — inclusive C14N already emits every declaration in scope — and an empty list is
     * indistinguishable from declaring none, so neither case emits an element.
     *
     * @param list<string> $prefixes
     *
     * @return list<callable>
     */
    private function inclusiveNamespaces(SignatureCanonicalization $canonicalization, array $prefixes): array
    {
        if (!$canonicalization->isExclusive() || $prefixes === []) {
            return [];
        }

        return [children(namespaced_element(
            SignatureCanonicalization::EXC_C14N->value,
            'ec:InclusiveNamespaces',
            attribute('PrefixList', implode(' ', $prefixes)),
        ))];
    }
}
