<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization;

use Dom\Element;
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
        ?Element $withoutSubtree = null,
    ): string {
        $restore = null;

        if ($withoutSubtree !== null) {
            // Nothing would be left to canonicalize, so this is refused rather than answered with the bytes of
            // the subtree the caller asked to exclude.
            if ($withoutSubtree->contains($node)) {
                throw CanonicalizationFailed::excludesEverything($node);
            }

            $restore = $this->lift($withoutSubtree);
        }

        try {
            // A libxml C14N failure must never escape as a raw exception through the SPI. The
            // InclusiveNamespaces PrefixList only has meaning for exclusive C14N, so it is passed only then.
            $canonical = disallow_libxml_false_returns(
                $node->C14N(
                    exclusive: $method->isExclusive(),
                    withComments: $method->withComments(),
                    nsPrefixes: $method->isExclusive() ? $inclusivePrefixes : null,
                ),
                'C14N produced no output',
            );
        } catch (DOMException | XmlException $exception) {
            throw CanonicalizationFailed::nativeError($node, $method, $exception);
        } finally {
            if ($restore !== null) {
                $restore();
            }
        }

        // An empty canonicalization must never reach a digest or signature.
        if ($canonical === '') {
            throw CanonicalizationFailed::emptyOutput($node, $method);
        }

        return $canonical;
    }

    /**
     * Lifts the subtree out of the document for the duration of one canonicalization, returning the callback
     * that puts it back exactly where it was. The same node instance returns to the same position, so callers
     * holding it (the coverage check compares by object identity) are unaffected.
     *
     * Every retained node keeps the ancestors it inherits namespace declarations from, and a declaration made
     * on the lifted element was only ever in scope inside it, so the canonical bytes are the same ones a
     * node-set filter produces. Cloning to the same shape would not be: a clone loses those ancestors.
     *
     * Filtering instead makes libxml test node-set membership per canonicalized node, which turns excluding a
     * signature from a wide element into quadratic work an attacker sizes.
     *
     * @return callable(): void
     */
    private function lift(Element $withoutSubtree): callable
    {
        $parent = $withoutSubtree->parentNode;
        if (!$parent instanceof Node) {
            return static function (): void {
            };
        }

        /** @var Node|null $nextSibling */
        $nextSibling = $withoutSubtree->nextSibling;
        $parent->removeChild($withoutSubtree);

        return static function () use ($parent, $withoutSubtree, $nextSibling): void {
            $parent->insertBefore($withoutSubtree, $nextSibling);
        };
    }
}
