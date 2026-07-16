<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization;

use Dom\Node;
use DOMException;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;
use VeeWee\Xml\Exception\RuntimeException as XmlException;
use function VeeWee\Xml\ErrorHandling\disallow_libxml_false_returns;

/**
 * The single seam between every XML-DSig operation and libxml's C14N primitive. Wraps native Dom\Node::C14N,
 * supports both exclusive and inclusive Canonical XML 1.0 (the canonicalizations the supported libxml floor
 * produces byte-for-byte correctly), and refuses an empty or failed canonicalization rather than letting it
 * be signed or compared.
 */
final class DomCanonicalizer implements Canonicalizer
{
    /**
     * @param list<string>|null $inclusivePrefixes
     *
     * @return non-empty-string
     *
     * @throws CanonicalizationFailed
     */
    public function canonicalize(
        Node $node,
        SignatureCanonicalization $method,
        ?array $inclusivePrefixes = null,
    ): string {
        try {
            // A libxml C14N failure must never escape as a raw exception through the SPI. The
            // InclusiveNamespaces PrefixList only has meaning for exclusive C14N, so it is passed only then.
            $canonical = disallow_libxml_false_returns(
                $node->C14N(
                    exclusive: $method->isExclusive(),
                    withComments: $method->withComments(),
                    xpath: null,
                    nsPrefixes: $method->isExclusive() ? $inclusivePrefixes : null,
                ),
                'C14N produced no output',
            );
        } catch (DOMException | XmlException $exception) {
            throw CanonicalizationFailed::nativeError($node, $method, $exception);
        }

        // An empty canonicalization must never reach a digest or signature.
        if ($canonical === '') {
            throw CanonicalizationFailed::emptyOutput($node, $method);
        }

        return $canonical;
    }
}
