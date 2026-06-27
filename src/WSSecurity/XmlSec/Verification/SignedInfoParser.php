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
     * @throws SignatureVerificationFailed
     */
    public function parse(Element $signature): ParsedSignedInfo
    {
        $signedInfo = $this->requireDsChild($signature, 'SignedInfo');

        $canonicalization = $this->signatureCanonicalization($signedInfo);
        $signatureMethod = $this->signatureMethod($signedInfo);
        [$referenceElements, $parsedReferences] = $this->parseReferences($signedInfo);

        return new ParsedSignedInfo($canonicalization, $signatureMethod, $referenceElements, $parsedReferences);
    }

    /**
     * @return array{0: non-empty-list<Element>, 1: non-empty-list<ParsedReference>}
     *
     * @throws SignatureVerificationFailed
     */
    private function parseReferences(Element $signedInfo): array
    {
        $elements = [];
        $parsed = [];
        foreach (ChildElements::named($signedInfo, WsseNamespace::Ds, 'Reference') as $child) {
            $elements[] = $child;
            $parsed[] = $this->parseReference($child);
        }

        if ($elements === [] || $parsed === []) {
            throw SignatureVerificationFailed::withReason('The signature declares no references.');
        }

        return [$elements, $parsed];
    }

    /**
     * @throws SignatureVerificationFailed
     */
    private function parseReference(Element $reference): ParsedReference
    {
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

        return new ParsedReference($wsuId, $digestMethod, trim((string) $digestValue->textContent));
    }

    /**
     * @throws SignatureVerificationFailed
     */
    private function signatureCanonicalization(Element $signedInfo): SignatureCanonicalization
    {
        $method = $this->requireDsChild($signedInfo, 'CanonicalizationMethod');
        $algorithm = SignatureCanonicalization::tryFrom((string) $method->getAttribute('Algorithm'));

        return $algorithm
            ?? throw SignatureVerificationFailed::withReason('The canonicalization method is unknown.');
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
