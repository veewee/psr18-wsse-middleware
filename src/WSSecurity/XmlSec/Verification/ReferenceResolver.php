<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdResolver;
use VeeWee\Xml\Dom\Document;

/**
 * Resolves each ds:Reference to the exact DOM element it describes.
 *
 * Before any element is located it refuses a reference list larger than MAX_REFERENCES: a small message that
 * declares an absurd number of references would otherwise amplify canonicalization and digest work far beyond
 * its own size, and a document-size limit cannot bound that because the message itself is small.
 *
 * For each reference it refuses any non-same-document URI, requires exactly one known c14n transform and
 * nothing else (which canonicalizations are actually accepted is decided upstream by the policy enforcer),
 * resolves the bare id through the hardened wsu:Id lookup (which refuses a duplicate id and never falls back to
 * getElementById), and refuses a reference that resolves to the ds:Signature element itself or anything inside
 * it. The returned element instances are exactly what the lookup produced and are never re-queried afterwards.
 */
final class ReferenceResolver
{
    /**
     * Upper bound on the number of ds:Reference entries a single ds:SignedInfo may declare. A conservative
     * ceiling far above any legitimate WSSE message; it could later move to the verification policy if a
     * deployment ever needs to tune it.
     */
    public const int MAX_REFERENCES = 32;

    /**
     * @param non-empty-list<Element> $referenceElements the ds:Reference DOM elements, document order
     * @param non-empty-list<ParsedReference> $parsedReferences the values parsed from those same references,
     *        in the same order
     *
     * @return non-empty-list<ResolvedVerificationReference>
     *
     * @throws SignatureVerificationFailed on a reference count over MAX_REFERENCES, or on any structural
     *         violation (missing or external URI, unknown transform, reference to ds:Signature itself,
     *         missing element, duplicate id)
     */
    public function resolve(
        Document $document,
        array $referenceElements,
        array $parsedReferences,
        Element $signatureElement,
    ): array {
        if (count($referenceElements) > self::MAX_REFERENCES) {
            throw SignatureVerificationFailed::withReason('The signature declares too many references.');
        }

        $resolved = [];
        foreach ($referenceElements as $index => $referenceElement) {
            $parsed = $parsedReferences[$index];
            $this->assertSingleKnownC14nTransform($referenceElement);

            $element = $this->locate($document, $referenceElement);
            $this->assertNotSignatureInfrastructure($element, $signatureElement);

            $resolved[] = new ResolvedVerificationReference(
                $element,
                $parsed->digestMethod,
                $parsed->expectedDigestValueBase64,
                $parsed->canonicalization,
                $parsed->inclusivePrefixes,
            );
        }

        return $resolved;
    }

    /**
     * Resolves the reference from the URI on its own ds:Reference element rather than trusting an id parsed
     * elsewhere, so the element that gets canonicalized is the one this exact reference points at.
     */
    private function locate(Document $document, Element $referenceElement): Element
    {
        $uri = (string) $referenceElement->getAttribute('URI');
        if (!str_starts_with($uri, '#') || $uri === '#') {
            throw SignatureVerificationFailed::withReason('A reference URI must be a non-empty same-document id.');
        }

        $id = substr($uri, 1);

        try {
            return WsuIdResolver::resolve($document, $id);
        } catch (IdReferenceException) {
            throw SignatureVerificationFailed::withReason('A referenced element could not be resolved.');
        }
    }

    private function assertSingleKnownC14nTransform(Element $referenceElement): void
    {
        $transforms = $this->onlyDsChild($referenceElement, 'Transforms');
        if ($transforms === null) {
            throw SignatureVerificationFailed::withReason('A reference declares no transform.');
        }

        $candidates = ChildElements::named($transforms, WsseNamespace::Ds, 'Transform');
        if (count($candidates) > 1) {
            throw SignatureVerificationFailed::withReason('A reference declares more than one transform.');
        }

        $transform = $candidates[0] ?? null;
        if ($transform === null
            || SignatureCanonicalization::tryFrom((string) $transform->getAttribute('Algorithm')) === null
        ) {
            throw SignatureVerificationFailed::withReason('A reference declares an unsupported transform.');
        }
    }

    private function assertNotSignatureInfrastructure(Element $element, Element $signatureElement): void
    {
        if ($element === $signatureElement || $this->isWithin($element, $signatureElement)) {
            throw SignatureVerificationFailed::withReason('A reference must not point at the signature itself.');
        }
    }

    private function isWithin(Node $element, Node $ancestor): bool
    {
        return ($ancestor->compareDocumentPosition($element) & Node::DOCUMENT_POSITION_CONTAINED_BY) !== 0;
    }

    private function onlyDsChild(Element $parent, string $localName): ?Element
    {
        $matches = ChildElements::named($parent, WsseNamespace::Ds, $localName);
        if (count($matches) > 1) {
            throw SignatureVerificationFailed::withReason(
                sprintf('ds:%s must appear at most once in a reference.', $localName),
            );
        }

        return $matches[0] ?? null;
    }
}
