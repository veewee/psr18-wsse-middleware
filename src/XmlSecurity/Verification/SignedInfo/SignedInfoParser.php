<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\SameDocumentId;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\PrefixList;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;

/**
 * Reads the ds:SignedInfo of a located ds:Signature into a structured ParsedSignedInfo: its
 * CanonicalizationMethod, its SignatureMethod, and the list of ds:Reference with each reference's
 * DigestMethod, DigestValue and same-document id.
 *
 * Each of ds:CanonicalizationMethod, ds:SignatureMethod, ds:DigestMethod and ds:DigestValue is required to
 * appear exactly once, so an injected sibling cannot shadow the real one. Every structural or unknown
 * algorithm failure surfaces as one SignatureVerificationFailed with a non-identifying message.
 */
final class SignedInfoParser
{
    /**
     * The transform that removes the enveloping signature from the node-set; it names no canonicalization.
     */
    private const ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    /**
     * @param non-empty-string|null       $externalTransform the one transform an external reference may
     *        declare, or null when the verification accepts no external reference at all
     * @param DereferencingTransform|null $dereferencingTransform the one transform an in-document reference may
     *        declare in place of a canonicalization, when the caller registered one
     *
     * @throws SignatureVerificationFailed
     */
    public function parse(
        Element $signature,
        ?string $externalTransform = null,
        ?DereferencingTransform $dereferencingTransform = null,
    ): ParsedSignedInfo {
        $signedInfo = $this->requireDsChild($signature, 'SignedInfo');

        $canonicalizationMethod = $this->requireDsChild($signedInfo, 'CanonicalizationMethod');
        $canonicalization = $this->canonicalizationAlgorithm($canonicalizationMethod);
        $canonicalizationPrefixes = PrefixList::read($canonicalizationMethod);
        $signatureMethod = $this->signatureMethod($signedInfo);
        [$referenceElements, $parsedReferences] = $this->parseReferences(
            $signedInfo,
            $externalTransform,
            $dereferencingTransform,
        );

        return new ParsedSignedInfo(
            $canonicalization,
            $canonicalizationPrefixes,
            $signatureMethod,
            $referenceElements,
            $parsedReferences,
        );
    }

    /**
     * @param non-empty-string|null $externalTransform
     *
     * @return array{0: non-empty-list<Element>, 1: non-empty-list<ParsedReference>}
     *
     * @throws SignatureVerificationFailed
     */
    private function parseReferences(
        Element $signedInfo,
        ?string $externalTransform,
        ?DereferencingTransform $transform,
    ): array {
        $elements = [];
        $parsed = [];
        foreach (ChildElements::named($signedInfo, Namespaces::Ds, 'Reference') as $child) {
            $elements[] = $child;
            $parsed[] = $this->parseReference($child, $externalTransform, $transform);
        }

        if ($elements === [] || $parsed === []) {
            throw SignatureVerificationFailed::withReason('The signature declares no references.');
        }

        return [$elements, $parsed];
    }

    /**
     * @param non-empty-string|null $externalTransform
     *
     * @throws SignatureVerificationFailed
     */
    private function parseReference(
        Element $reference,
        ?string $externalTransform,
        ?DereferencingTransform $transform,
    ): ParsedReference {
        // The id itself is re-read from the element by the resolver; here it only has to be well-formed.
        if (SameDocumentId::parse((string) $reference->getAttribute('URI')) === null) {
            // Not a same-document id. It is an external reference only if this verification accepts them and
            // the reference declares exactly the transform it was told to expect. Otherwise the standing
            // refusal applies: an external URI is never resolved, and never fetched.
            if ($externalTransform === null) {
                throw SignatureVerificationFailed::withReason(
                    'A reference URI must be a non-empty same-document id.',
                );
            }

            return new ParsedReference(
                $this->digestMethod($reference),
                ElementText::trimmed($this->requireDsChild($reference, 'DigestValue')),
                null,
                [],
                $this->assertExternalTransform($reference, $externalTransform),
            );
        }

        $digestMethod = $this->digestMethod($reference);
        $digestValue = $this->requireDsChild($reference, 'DigestValue');
        // A reference declaring the registered indirection is canonicalized the way that transform says, and
        // records which one it was. Every other reference keeps the ordinary pipeline the engine already reads.
        $dereferencing = $this->declaredDereferencingTransform($reference, $transform);
        if ($transform === null || $dereferencing === null) {
            $ordinary = $this->referenceCanonicalization($reference);

            return new ParsedReference(
                $digestMethod,
                ElementText::trimmed($digestValue),
                $ordinary->canonicalization,
                $ordinary->inclusivePrefixes,
            );
        }

        $how = $transform->canonicalization($dereferencing);

        return new ParsedReference(
            $digestMethod,
            ElementText::trimmed($digestValue),
            $how->canonicalization,
            $how->inclusivePrefixes,
            dereferencingTransform: $transform->algorithm(),
        );
    }

    /**
     * Resolves the canonicalization a reference's digest is computed under. When ds:Transforms is present it
     * must declare exactly one c14n transform and nothing else; the optional PrefixList of an exclusive
     * transform is read. When ds:Transforms is absent the reference's node-set is converted to octets with
     * inclusive Canonical XML, the conversion XML-DSig prescribes when no transform says otherwise. Not with
     * whatever SignedInfo declares for itself, which governs only SignedInfo. Whether the resolved
     * canonicalization is accepted at all is decided later by the policy enforcer, not here: the default
     * allow-list is exclusive-only, so a transform-less reference is refused there unless a deployment opts
     * inclusive c14n in.
     *
     * @throws SignatureVerificationFailed
     */
    private function referenceCanonicalization(Element $reference): TransformCanonicalization
    {
        $transformsMatches = ChildElements::named($reference, Namespaces::Ds, 'Transforms');
        if (count($transformsMatches) > 1) {
            throw SignatureVerificationFailed::withReason('ds:Transforms must appear at most once in a reference.');
        }

        $transforms = $transformsMatches[0] ?? null;
        if ($transforms === null) {
            return new TransformCanonicalization(SignatureCanonicalization::C14N, []);
        }

        // The pipeline may open with the enveloped-signature transform, which names no canonicalization of its
        // own; the canonicalization is whichever transform follows it. Which sequences are legal is decided by
        // ReferenceResolver, so this reads the method and refuses only what it cannot read.
        $declared = ChildElements::named($transforms, Namespaces::Ds, 'Transform');
        $candidates = array_values(array_filter(
            $declared,
            static fn (Element $transform): bool => (string) $transform->getAttribute('Algorithm')
                !== self::ENVELOPED_SIGNATURE,
        ));

        if ($candidates === []) {
            // Enveloped-signature alone: the default canonicalization applies, as for an absent ds:Transforms.
            return new TransformCanonicalization(SignatureCanonicalization::C14N, []);
        }

        $transform = count($candidates) === 1
            ? $candidates[0]
            : throw SignatureVerificationFailed::withReason('A reference must declare exactly one transform.');

        $algorithm = SignatureCanonicalization::tryFrom((string) $transform->getAttribute('Algorithm'));
        if ($algorithm === null) {
            throw SignatureVerificationFailed::withReason('A reference transform is not a known canonicalization.');
        }

        return new TransformCanonicalization($algorithm, PrefixList::read($transform));
    }

    /**
     * An external reference must declare exactly the one transform the verification expects, and nothing else.
     * No default applies here and none could: the transform is what says the digest covers a stream of octets
     * rather than a canonicalized node-set, so an absent or unexpected one leaves the digest undefined.
     *
     * @param non-empty-string $required
     *
     * @return non-empty-string
     *
     * @throws SignatureVerificationFailed
     */
    private function assertExternalTransform(Element $reference, string $required): string
    {
        $transformsMatches = ChildElements::named($reference, Namespaces::Ds, 'Transforms');
        if (count($transformsMatches) !== 1) {
            throw SignatureVerificationFailed::withReason('An external reference must declare one transform.');
        }

        $declared = ChildElements::named($transformsMatches[0], Namespaces::Ds, 'Transform');
        if (count($declared) !== 1) {
            throw SignatureVerificationFailed::withReason('An external reference must declare one transform.');
        }

        if ((string) $declared[0]->getAttribute('Algorithm') !== $required) {
            throw SignatureVerificationFailed::withReason('A reference declares an unsupported transform.');
        }

        return $required;
    }

    /**
     * @throws SignatureVerificationFailed
     */
    private function canonicalizationAlgorithm(Element $canonicalizationMethod): SignatureCanonicalization
    {
        $algorithm = SignatureCanonicalization::tryFrom((string) $canonicalizationMethod->getAttribute('Algorithm'));

        return $algorithm
            ?? throw SignatureVerificationFailed::withReason('The canonicalization method is unknown.');
    }

    /**
     * The ds:Transform declaring the registered transform's algorithm, or null when the reference declares an
     * ordinary canonicalization pipeline. A reference may declare it only once and alone: pairing an
     * indirection with another transform describes two different computations, and picking one is a choice a
     * signer must not get to make for the verifier.
     *
     * @throws SignatureVerificationFailed
     */
    private function declaredDereferencingTransform(
        Element $reference,
        ?DereferencingTransform $transform,
    ): ?Element {
        if ($transform === null) {
            return null;
        }

        $transforms = ChildElements::named($reference, Namespaces::Ds, 'Transforms');
        if (count($transforms) !== 1) {
            return null;
        }

        $declared = ChildElements::named($transforms[0], Namespaces::Ds, 'Transform');
        $matching = array_values(array_filter(
            $declared,
            static fn (Element $candidate): bool =>
                (string) $candidate->getAttribute('Algorithm') === $transform->algorithm(),
        ));

        if ($matching === []) {
            return null;
        }

        if (count($declared) !== 1) {
            throw SignatureVerificationFailed::withReason(
                'A dereferencing transform must be the only transform a reference declares.',
            );
        }

        return $matching[0];
    }

    /**
     * @throws SignatureVerificationFailed
     */
    private function signatureMethod(Element $signedInfo): SignatureMethod
    {
        $method = $this->requireDsChild($signedInfo, 'SignatureMethod');
        $algorithm = SignatureMethod::tryFrom((string) $method->getAttribute('Algorithm'));

        return $algorithm
            ?? throw SignatureVerificationFailed::withReason('The signature method is unknown.');
    }

    /**
     * @throws SignatureVerificationFailed
     */
    private function digestMethod(Element $reference): DigestMethod
    {
        $method = $this->requireDsChild($reference, 'DigestMethod');
        $algorithm = DigestMethod::tryFrom((string) $method->getAttribute('Algorithm'));

        return $algorithm
            ?? throw SignatureVerificationFailed::withReason('A digest method is unknown.');
    }

    /**
     * @throws SignatureVerificationFailed
     */
    private function requireDsChild(Element $parent, string $localName): Element
    {
        // Exactly one, so a second injected ds:DigestMethod/ds:DigestValue cannot shadow the real one.
        return ChildElements::single($parent, Namespaces::Ds, $localName)
            ?? throw SignatureVerificationFailed::withReason(
                sprintf('ds:%s must appear exactly once.', $localName),
            );
    }
}
