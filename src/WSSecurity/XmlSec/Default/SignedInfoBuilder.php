<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * Assembles a ds:SignedInfo element with ds:CanonicalizationMethod, ds:SignatureMethod, and one ds:Reference
 * per DigestResult. The returned element is detached; the caller attaches it as a child of ds:Signature.
 *
 * Each ds:Reference declares the exclusive-C14N transform it was digested with, so a verifier canonicalizes
 * the referenced element the same way before checking the digest.
 */
final class SignedInfoBuilder
{
    private const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

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
            fn (DigestResult $result): callable => $this->reference($result),
            $references,
        );

        return $document->map(namespaced_element(
            WsseNamespace::Ds->value,
            WsseNamespace::Ds->qualify('SignedInfo'),
            children(
                namespaced_element(
                    WsseNamespace::Ds->value,
                    WsseNamespace::Ds->qualify('CanonicalizationMethod'),
                    attribute('Algorithm', $canonicalization->value),
                ),
                namespaced_element(
                    WsseNamespace::Ds->value,
                    WsseNamespace::Ds->qualify('SignatureMethod'),
                    attribute('Algorithm', $signatureMethod->value),
                ),
                ...$referenceBuilders,
            ),
        ));
    }

    /**
     * @return callable(Element): Element
     */
    private function reference(DigestResult $result): callable
    {
        return namespaced_element(
            WsseNamespace::Ds->value,
            WsseNamespace::Ds->qualify('Reference'),
            attribute('URI', '#'.$result->wsuId),
            children(
                namespaced_element(
                    WsseNamespace::Ds->value,
                    WsseNamespace::Ds->qualify('Transforms'),
                    children(namespaced_element(
                        WsseNamespace::Ds->value,
                        WsseNamespace::Ds->qualify('Transform'),
                        attribute('Algorithm', self::EXC_C14N),
                    )),
                ),
                namespaced_element(
                    WsseNamespace::Ds->value,
                    WsseNamespace::Ds->qualify('DigestMethod'),
                    attribute('Algorithm', $result->digestMethod->value),
                ),
                namespaced_element(
                    WsseNamespace::Ds->value,
                    WsseNamespace::Ds->qualify('DigestValue'),
                    value($result->digestValueBase64),
                ),
            ),
        );
    }
}
