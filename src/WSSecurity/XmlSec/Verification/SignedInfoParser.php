<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use function VeeWee\Xml\Dom\Locator\Element\children;

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
     * The exclusive-c14n namespace that carries the optional InclusiveNamespaces PrefixList element.
     */
    private const EXC_C14N_NAMESPACE = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    /**
     * @throws SignatureVerificationFailed
     */
    public function parse(Element $signature): ParsedSignedInfo
    {
        $signedInfo = $this->requireDsChild($signature, 'SignedInfo');

        $canonicalizationMethod = $this->requireDsChild($signedInfo, 'CanonicalizationMethod');
        $canonicalization = $this->canonicalizationAlgorithm($canonicalizationMethod);
        $canonicalizationPrefixes = $this->inclusivePrefixes($canonicalizationMethod);
        $signatureMethod = $this->signatureMethod($signedInfo);
        [$referenceElements, $parsedReferences] = $this->parseReferences($signedInfo, $canonicalization);

        return new ParsedSignedInfo(
            $canonicalization,
            $canonicalizationPrefixes,
            $signatureMethod,
            $referenceElements,
            $parsedReferences,
        );
    }

    /**
     * @return array{0: non-empty-list<Element>, 1: non-empty-list<ParsedReference>}
     *
     * @throws SignatureVerificationFailed
     */
    private function parseReferences(Element $signedInfo, SignatureCanonicalization $signedInfoCanonicalization): array
    {
        $elements = [];
        $parsed = [];
        foreach (ChildElements::named($signedInfo, WsseNamespace::Ds, 'Reference') as $child) {
            $elements[] = $child;
            $parsed[] = $this->parseReference($child, $signedInfoCanonicalization);
        }

        if ($elements === [] || $parsed === []) {
            throw SignatureVerificationFailed::withReason('The signature declares no references.');
        }

        return [$elements, $parsed];
    }

    /**
     * @throws SignatureVerificationFailed
     */
    private function parseReference(
        Element $reference,
        SignatureCanonicalization $signedInfoCanonicalization,
    ): ParsedReference {
        $uri = (string) $reference->getAttribute('URI');
        if (!str_starts_with($uri, '#') || $uri === '#') {
            throw SignatureVerificationFailed::withReason('A reference URI must be a non-empty same-document id.');
        }

        $wsuId = substr($uri, 1);
        if ($wsuId === '') {
            throw SignatureVerificationFailed::withReason('A reference URI must be a non-empty same-document id.');
        }

        $digestMethod = $this->digestMethod($reference);
        $digestValue = $this->requireDsChild($reference, 'DigestValue');
        [$canonicalization, $inclusivePrefixes] = $this->referenceCanonicalization(
            $reference,
            $signedInfoCanonicalization,
        );

        return new ParsedReference(
            $wsuId,
            $digestMethod,
            trim((string) $digestValue->textContent),
            $canonicalization,
            $inclusivePrefixes,
        );
    }

    /**
     * Resolves the canonicalization a reference's digest is computed under. When ds:Transforms is present it
     * must declare exactly one exclusive-c14n transform and nothing else; its optional PrefixList is read.
     * When ds:Transforms is absent the digest is taken under the SignedInfo canonicalization with no prefixes,
     * which preserves the behaviour for signers that omit Transforms.
     *
     * @return array{0: SignatureCanonicalization, 1: list<string>}
     *
     * @throws SignatureVerificationFailed
     */
    private function referenceCanonicalization(
        Element $reference,
        SignatureCanonicalization $signedInfoCanonicalization,
    ): array {
        $transformsMatches = ChildElements::named($reference, WsseNamespace::Ds, 'Transforms');
        if (count($transformsMatches) > 1) {
            throw SignatureVerificationFailed::withReason('ds:Transforms must appear at most once in a reference.');
        }

        $transforms = $transformsMatches[0] ?? null;
        if ($transforms === null) {
            return [$signedInfoCanonicalization, []];
        }

        $transformElements = ChildElements::named($transforms, WsseNamespace::Ds, 'Transform');
        if (count($transformElements) !== 1) {
            throw SignatureVerificationFailed::withReason('A reference must declare exactly one transform.');
        }

        $transform = $transformElements[0];
        $algorithm = SignatureCanonicalization::tryFrom((string) $transform->getAttribute('Algorithm'));
        if ($algorithm === null || !$algorithm->isExclusive()) {
            throw SignatureVerificationFailed::withReason('A reference transform is not an accepted canonicalization.');
        }

        return [$algorithm, $this->inclusivePrefixes($transform)];
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
     * Reads the optional exclusive-c14n InclusiveNamespaces PrefixList carried as a direct child of a
     * canonicalization element, split on whitespace. An absent or empty list yields an empty list.
     *
     * @return list<string>
     *
     * @throws SignatureVerificationFailed
     */
    private function inclusivePrefixes(Element $canonicalizationElement): array
    {
        $matches = children($canonicalizationElement)
            ->filter(
                static fn (Element $child): bool => $child->localName === 'InclusiveNamespaces'
                    && $child->namespaceURI === self::EXC_C14N_NAMESPACE,
            )
            ->map(static fn (Element $child): Element => $child);

        if (count($matches) > 1) {
            throw SignatureVerificationFailed::withReason('ec:InclusiveNamespaces must appear at most once.');
        }

        $inclusiveNamespaces = $matches[0] ?? null;
        if ($inclusiveNamespaces === null) {
            return [];
        }

        $prefixList = trim((string) $inclusiveNamespaces->getAttribute('PrefixList'));
        if ($prefixList === '') {
            return [];
        }

        return array_values(array_filter(
            preg_split('/\s+/', $prefixList) ?: [],
            static fn (string $prefix): bool => $prefix !== '',
        ));
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
        $matches = ChildElements::named($parent, WsseNamespace::Ds, $localName);
        if (count($matches) !== 1) {
            throw SignatureVerificationFailed::withReason(sprintf('ds:%s must appear exactly once.', $localName));
        }

        return $matches[0];
    }
}
