<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Canonicalization;

use Dom\Node;
use DOMException;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\CanonicalizationFailed;
use VeeWee\Xml\Exception\RuntimeException as XmlException;
use function VeeWee\Xml\ErrorHandling\disallow_libxml_false_returns;

/**
 * The single seam between every XML-DSig operation and libxml's C14N primitive. Wraps native Dom\Node::C14N,
 * supports exclusive C14N only (the WS-Security norm, and the canonicalization the supported libxml floor
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
        // Inclusive C14N silently drops inherited namespaces on the new DOM, so it would sign wrong bytes.
        if (!$method->isExclusive()) {
            throw CanonicalizationFailed::unsupportedAlgorithm($method);
        }

        try {
            // A libxml C14N failure must never escape as a raw exception through the SPI.
            $canonical = disallow_libxml_false_returns(
                $node->C14N(
                    exclusive: true,
                    withComments: $method->withComments(),
                    xpath: null,
                    nsPrefixes: $inclusivePrefixes,
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
