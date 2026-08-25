<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo;

use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\Query;
use Soap\Psr18WsseMiddleware\Xml\SameDocumentId;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\ExternalPartVerification;
use VeeWee\Xml\Dom\Document;

/**
 * Resolves each ds:Reference to the exact DOM element it describes.
 *
 * Before any element is located it refuses a reference list larger than MAX_REFERENCES: a small message that
 * declares an absurd number of references would otherwise amplify canonicalization and digest work far beyond
 * its own size, and a document-size limit cannot bound that because the message itself is small.
 *
 * A cid: reference is the one narrow exception to the non-same-document refusal, and only when the caller
 * supplied the parts: the reference must name one of them, its digest is computed over that part's octets, and
 * the URI is never dereferenced. Without those parts every non-fragment URI stays refused.
 *
 * For each in-document reference it refuses any non-same-document URI, requires a declared ds:Transforms to hold exactly
 * one known c14n transform and nothing else (which canonicalizations are actually accepted is decided
 * upstream by the policy enforcer, and an absent ds:Transforms is left to the parser, which digests under
 * inclusive c14n), resolves the bare id through the injected IdLookup (hardened to refuse a duplicate id and
 * never fall back to getElementById), and refuses a reference that resolves to the ds:Signature element itself
 * or anything inside it. The returned element instances are exactly what the lookup produced and are never
 * re-queried afterwards.
 */
final class ReferenceResolver
{
    /**
     * The transform that removes the signature from the node-set of the element it is enveloped in. Mandatory in
     * XML-DSig and the shape a signed SAML assertion arrives in.
     */
    private const ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    /**
     * Upper bound on the number of ds:Reference entries a single ds:SignedInfo may declare. A conservative
     * ceiling far above any legitimate message; it could later move to the verification policy if a
     * deployment ever needs to tune it.
     */
    public const int MAX_REFERENCES = 32;

    public function __construct(
        private IdLookup $idLookup,
    ) {
    }

    /**
     * @param non-empty-list<Element> $referenceElements the ds:Reference DOM elements, document order
     * @param non-empty-list<ParsedReference> $parsedReferences the values parsed from those same references,
     *        in the same order
     *
     * @throws SignatureVerificationFailed on a reference count over MAX_REFERENCES, or on any structural
     *         violation (missing or external URI, unknown transform, reference to ds:Signature itself,
     *         missing element, duplicate id, or an external reference naming a part that was not supplied)
     */
    public function resolve(
        Document $document,
        array $referenceElements,
        array $parsedReferences,
        Element $signatureElement,
        ?ExternalPartVerification $external = null,
    ): ResolvedReferences {
        if (count($referenceElements) > self::MAX_REFERENCES) {
            throw SignatureVerificationFailed::withReason('The signature declares too many references.');
        }

        $elements = [];
        $externalReferences = [];
        foreach ($referenceElements as $index => $referenceElement) {
            $parsed = $parsedReferences[$index];

            if ($parsed->isExternal()) {
                $externalReferences[] = new ResolvedExternalReference(
                    $parsed,
                    $this->locateExternalPart($referenceElement, $external),
                );

                continue;
            }

            $this->assertSingleKnownC14nTransform($referenceElement);

            $id = $this->referenceId($referenceElement);
            $element = $this->locate($document, $id);
            $this->assertNotSignatureInfrastructure($element, $signatureElement);

            $elements[] = new ResolvedVerificationReference(
                $parsed,
                $element,
                $id,
                $this->declaresEnvelopedSignature($referenceElement)
                    ? $this->signatureToStrip($document, $element, $signatureElement)
                    : null,
            );
        }

        return new ResolvedReferences($elements, $externalReferences);
    }

    /**
     * The caller-supplied part a reference URI names, matched verbatim.
     *
     * Never dereferenced and never searched for anywhere else: a URI that matches no supplied part is refused
     * outright. That is what keeps this a lookup in a list the caller controls rather than a fetch a signature
     * can aim wherever it likes.
     *
     * @throws SignatureVerificationFailed
     */
    private function locateExternalPart(
        Element $referenceElement,
        ?ExternalPartVerification $external,
    ): ExternalPart {
        if ($external === null) {
            // Unreachable through the parser, which only produces an external reference when it was given a
            // transform to expect. Kept so this method is safe in its own right rather than by that argument.
            throw SignatureVerificationFailed::withReason('A referenced element could not be resolved.');
        }

        $uri = (string) $referenceElement->getAttribute('URI');

        return $external->parts->byReference($uri)
            ?? throw SignatureVerificationFailed::withReason('A referenced element could not be resolved.');
    }

    /**
     * The bare id from a ds:Reference's own URI, read from the reference element rather than trusting an id
     * parsed elsewhere, so the element that gets canonicalized is the one this exact reference points at.
     *
     * @return non-empty-string
     */
    private function referenceId(Element $referenceElement): string
    {
        return SameDocumentId::parse((string) $referenceElement->getAttribute('URI'))
            ?? throw SignatureVerificationFailed::withReason(
                'A reference URI must be a non-empty same-document id.',
            );
    }

    /**
     * @param non-empty-string $id
     */
    private function locate(Document $document, string $id): Element
    {
        try {
            return $this->idLookup->lookup($document, $id);
        } catch (IdReferenceException) {
            throw SignatureVerificationFailed::withReason('A referenced element could not be resolved.');
        }
    }

    /**
     * A reference that declares no ds:Transforms at all is left to the parser, which digests it under
     * inclusive c14n; the element is spec-legal and some signers emit it. What is refused here is a
     * ds:Transforms that declares something other than one known canonicalization.
     */
    private function assertSingleKnownC14nTransform(Element $referenceElement): void
    {
        $algorithms = $this->declaredTransforms($referenceElement);
        if ($algorithms === null) {
            return;
        }

        // Transforms are an ordered pipeline, so the enveloped-signature transform is only recognised in the
        // position where it means what it says: strip the signature, then canonicalize what is left. The
        // reversed order is a different computation and is not treated as equivalent.
        if ($algorithms !== [] && $algorithms[0] === self::ENVELOPED_SIGNATURE) {
            array_shift($algorithms);
        }

        if ($algorithms === []) {
            // Enveloped-signature alone is spec-legal: with no canonicalization named the default applies,
            // exactly as for a reference declaring no transforms at all.
            return;
        }

        if (count($algorithms) > 1) {
            throw SignatureVerificationFailed::withReason('A reference declares more than one transform.');
        }

        if (SignatureCanonicalization::tryFrom($algorithms[0]) === null) {
            throw SignatureVerificationFailed::withReason('A reference declares an unsupported transform.');
        }
    }

    /**
     * The transform algorithms a reference declares, in document order, or null when it declares no
     * ds:Transforms at all.
     *
     * @return list<string>|null
     */
    private function declaredTransforms(Element $referenceElement): ?array
    {
        $transforms = $this->onlyDsChild($referenceElement, 'Transforms');
        if ($transforms === null) {
            return null;
        }

        $algorithms = [];
        foreach (ChildElements::named($transforms, Namespaces::Ds, 'Transform') as $transform) {
            $algorithms[] = (string) $transform->getAttribute('Algorithm');
        }

        return $algorithms;
    }

    private function declaresEnvelopedSignature(Element $referenceElement): bool
    {
        $algorithms = $this->declaredTransforms($referenceElement) ?? [];

        return ($algorithms[0] ?? null) === self::ENVELOPED_SIGNATURE;
    }

    /**
     * The one ds:Signature to leave out of this element's digest.
     *
     * The transform removes the signature that contains it, not any signature in the document. Stripping every
     * ds:Signature under the element would let an injected second one be dropped from the digest silently, so
     * more than one is refused outright rather than resolved by picking, and the single one must be, by object
     * identity, the signature being verified. An element holding none is refused too: the transform claims
     * self-exclusion while the signature sits elsewhere, which is a relocated signature claiming coverage of an
     * element it is not inside.
     *
     * @throws SignatureVerificationFailed
     */
    private function signatureToStrip(Document $document, Element $element, Element $signatureElement): Element
    {
        $contained = Query::elements(
            $document,
            './/'.Namespaces::Ds->qualify('Signature'),
            $element,
            [Namespaces::Ds->prefix() => Namespaces::Ds->uri()],
        )
            ->map(static fn (Element $candidate): Element => $candidate);

        if (count($contained) !== 1 || $contained[0] !== $signatureElement) {
            throw SignatureVerificationFailed::withReason(
                'An enveloped-signature reference must cover exactly the element holding this signature.',
            );
        }

        return $signatureElement;
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
        $matches = ChildElements::named($parent, Namespaces::Ds, $localName);
        if (count($matches) > 1) {
            throw SignatureVerificationFailed::withReason(
                sprintf('ds:%s must appear at most once in a reference.', $localName),
            );
        }

        return $matches[0] ?? null;
    }
}
