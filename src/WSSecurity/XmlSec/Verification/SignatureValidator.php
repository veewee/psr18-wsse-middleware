<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\ElementText;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Canonicalization\Canonicalizer;

/**
 * Validates the signature value over ds:SignedInfo. It asserts the structural invariants the XML Signature
 * spec requires before any cryptographic work runs: exactly one ds:SignedInfo, one ds:SignatureValue and one
 * ds:KeyInfo as direct children of ds:Signature, with ds:SignedInfo preceding ds:SignatureValue, and exactly
 * one ds:CanonicalizationMethod and one ds:SignatureMethod inside ds:SignedInfo. Only then does it
 * canonicalize ds:SignedInfo and ask the OpenSSL boundary whether the signature value verifies.
 *
 * A forged or malformed signature value is a normal cryptographic outcome reported as false, with no detail
 * that would distinguish a wrong key from garbage bytes. Structural violations are refused before the crypto
 * call. A canonicalization failure propagates unchanged.
 */
final class SignatureValidator
{
    public function __construct(
        private Canonicalizer $canonicalizer,
        private OpenSslSigner $opensslSigner,
    ) {
    }

    /**
     * @param list<string> $inclusivePrefixes the exclusive-c14n PrefixList used when canonicalizing ds:SignedInfo
     *
     * @throws SignatureVerificationFailed when the ds:Signature structure is invalid
     * @throws CanonicalizationFailed when ds:SignedInfo cannot be canonicalized (propagated)
     */
    public function validate(
        Element $signatureElement,
        Certificate $signerCertificate,
        SignatureMethod $signatureMethod,
        SignatureCanonicalization $canonicalizationMethod,
        array $inclusivePrefixes,
    ): bool {
        $signedInfo = $this->onlyChild($signatureElement, 'SignedInfo');
        $signatureValue = $this->onlyChild($signatureElement, 'SignatureValue');
        $this->onlyChild($signatureElement, 'KeyInfo');

        if (!$this->precedes($signedInfo, $signatureValue)) {
            throw SignatureVerificationFailed::withReason('ds:SignedInfo must precede ds:SignatureValue.');
        }

        $this->onlyChild($signedInfo, 'CanonicalizationMethod');
        $this->onlyChild($signedInfo, 'SignatureMethod');

        $expectedSignature = base64_decode(ElementText::trimmed($signatureValue), true);
        if ($expectedSignature === false) {
            throw SignatureVerificationFailed::withReason('The signature value is not valid base64.');
        }

        $canonical = $this->canonicalizer->canonicalize(
            $signedInfo,
            $canonicalizationMethod,
            $inclusivePrefixes === [] ? null : $inclusivePrefixes,
        );

        try {
            return $this->opensslSigner->verify($signerCertificate, $canonical, $expectedSignature, $signatureMethod);
        } catch (OpenSslException) {
            // A key or setup error: treated as a failed verification so the caller learns only that the
            // signature did not verify.
            return false;
        }
    }

    /**
     * @throws SignatureVerificationFailed when the element does not have exactly one such ds: child
     */
    private function onlyChild(Element $parent, string $localName): Element
    {
        $matches = ChildElements::named($parent, Namespaces::Ds, $localName);
        if (count($matches) !== 1) {
            throw SignatureVerificationFailed::withReason(sprintf('ds:%s must appear exactly once.', $localName));
        }

        return $matches[0];
    }

    private function precedes(Node $first, Node $second): bool
    {
        return ($first->compareDocumentPosition($second) & Node::DOCUMENT_POSITION_FOLLOWING) !== 0;
    }
}
