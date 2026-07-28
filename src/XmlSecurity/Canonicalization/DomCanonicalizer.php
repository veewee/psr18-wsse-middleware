<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization;

use Dom\Element;
use Dom\Node;
use DOMException;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;
use VeeWee\Xml\Exception\RuntimeException as XmlException;
use function VeeWee\Xml\Dom\Locator\Element\children;
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
        ?Element $withoutSubtree = null,
    ): string {
        try {
            // A libxml C14N failure must never escape as a raw exception through the SPI. The
            // InclusiveNamespaces PrefixList only has meaning for exclusive C14N, so it is passed only then.
            $canonical = disallow_libxml_false_returns(
                $node->C14N(
                    exclusive: $method->isExclusive(),
                    withComments: $method->withComments(),
                    xpath: $withoutSubtree === null ? null : $this->nodeSetWithout($withoutSubtree),
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

    /**
     * The node-set of the canonicalized subtree with one descendant subtree filtered out.
     *
     * libxml applies this selection while canonicalizing in place, so the excluded node is never detached and
     * every namespace declaration the retained nodes inherit from their ancestors is still in scope. Removing or
     * cloning to achieve the same shape would change the canonical bytes and break the digest.
     *
     * The subtree is addressed by an absolute positional path. That identifies the one node the caller resolved
     * rather than matching on a name, which would drop every element sharing it, and it carries no namespace
     * prefixes, so the query needs no prefix bindings to evaluate.
     *
     * @return array{query: string, namespaces: array<string, string>}
     */
    private function nodeSetWithout(Element $withoutSubtree): array
    {
        $path = $this->absolutePositionalPath($withoutSubtree);

        return [
            'query' => '(.//. | .//@* | .//namespace::*)[not(ancestor-or-self::node()[count(. | '
                .$path.') = count('.$path.')])]',
            'namespaces' => [],
        ];
    }

    /**
     * An absolute XPath addressing exactly one element by its position among its element siblings at each step.
     */
    private function absolutePositionalPath(Element $element): string
    {
        $steps = [];
        $node = $element;

        while (true) {
            $parent = $node->parentNode;
            $steps[] = '*['.($parent instanceof Element ? $this->positionWithin($parent, $node) : 1).']';

            if (!$parent instanceof Element) {
                break;
            }

            $node = $parent;
        }

        return '/'.implode('/', array_reverse($steps));
    }

    /**
     * The one-based position of a child among its parent's element children, compared by object identity so a
     * look-alike sibling cannot be mistaken for it.
     *
     * @return positive-int
     */
    private function positionWithin(Element $parent, Element $child): int
    {
        $position = 0;
        foreach (children($parent) as $element) {
            ++$position;
            if ($element === $child) {
                return $position;
            }
        }

        // Unreachable for a child of this parent; refusing beats emitting a path that addresses the wrong node.
        throw CanonicalizationFailed::emptyOutput($child, SignatureCanonicalization::EXC_C14N);
    }
}
