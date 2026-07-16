<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Dom\Element;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\WsuId;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator\NodeOrder;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Query;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\Canonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SigningFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\ResolvedReference;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;
use function VeeWee\Xml\Dom\Manipulator\append;

/**
 * Orchestrates the WSSE signing flow: resolve Parts to (element, wsu:Id) pairs (minting ids as needed),
 * digest each element, assemble ds:SignedInfo, canonicalize and sign it, build ds:KeyInfo, then assemble the
 * detached ds:Signature, append it to the existing wsse:Security header, and re-sort the header.
 *
 * The Security header is located from the document (the WSSE namespace is fixed regardless of SOAP version),
 * so this carries no SOAP-version or mustUnderstand dependency; the outbound caller must create the header
 * before signing. The signature is inserted last, so no Part can resolve to it. The private key never leaves
 * the OpenSSL\ boundary: its Key is handed to OpenSSL\Signer, which resolves the live handle internally.
 *
 * Mutates the document in place (wsu:Id stamps on referenced elements, then ds:Signature insertion).
 */
final class Signer implements XmlSigner
{
    public function __construct(
        private ReferenceCollector $referenceCollector,
        private DigestCalculator $digestCalculator,
        private SignedInfoBuilder $signedInfoBuilder,
        private KeyInfoBuilder $keyInfoBuilder,
        private Canonicalizer $canonicalizer,
        private OpenSslSigner $opensslSigner,
    ) {
    }

    public function sign(Document $document, SigningRequest $request): void
    {
        $security = $this->locateSecurity($document);

        $references = $this->referenceCollector->collect($document, $request->parts);

        // Digest a fresh parse of the serialized document, not the live DOM. Elements minted with
        // createElementNS carry namespace declarations the live DOM omits but the serialized wire
        // materialises; inclusive C14N folds those declarations into the digest, so digesting the live DOM
        // would produce bytes no verifier reading the wire could reproduce. The reparse is exactly what the
        // wire is, so the digests match across libxml versions.
        $wire = $this->wire($document);
        $digests = array_map(
            fn (ResolvedReference $reference): DigestResult => $this->digestCalculator->calculate(
                new ResolvedReference(WsuId::resolve($wire, $reference->wsuId), $reference->wsuId),
                $request->canonicalization,
                $request->digestMethod,
            ),
            $references,
        );

        $signedInfo = $this->signedInfoBuilder->build(
            $document,
            $request->canonicalization,
            $request->signatureMethod,
            $digests,
        );
        $keyInfo = $this->keyInfoBuilder->build($document, $request->keyIdentifier, $request->signingCertificate);

        // The signature is attached first so ds:SignedInfo is in-document: C14N only works on attached nodes,
        // and the signed bytes are the canonical form of SignedInfo as it sits inside the signed message.
        $signatureValue = $this->buildSignatureValueElement($document);
        $signature = $this->buildSignature($document, $signedInfo, $signatureValue, $keyInfo);
        append($signature)($security);
        NodeOrder::sort($security);

        $this->signInto($signatureValue, $request, $document);
    }

    /**
     * @throws SigningFailed
     */
    private function locateSecurity(Document $document): Element
    {
        return SecurityHeader::locate($document) ?? throw SigningFailed::missingSecurityHeader();
    }

    /**
     * Canonicalizes ds:SignedInfo from a fresh parse of the now-complete document, signs it, and writes the
     * base64 signature into the ds:SignatureValue element. SignedInfo carries the same live-versus-wire
     * namespace divergence as the signed parts, so the bytes that get signed must be the wire bytes a
     * verifier re-canonicalizes, not the live DOM bytes.
     *
     * @throws SigningFailed
     */
    private function signInto(Element $signatureValue, SigningRequest $request, Document $document): void
    {
        $signedInfo = $this->locateSignedInfo($this->wire($document));
        $canonical = $this->canonicalizer->canonicalize($signedInfo, $request->canonicalization);

        try {
            $signature = $this->opensslSigner->sign($request->signingKey, $canonical, $request->signatureMethod);
        } catch (OpenSslException $exception) {
            throw SigningFailed::cryptoError($exception->getMessage());
        }

        value(base64_encode($signature))($signatureValue);
    }

    /**
     * The serialized document parsed back into a fresh DOM: exactly the bytes that travel on the wire and the
     * tree a verifier re-canonicalizes from.
     */
    private function wire(Document $document): Document
    {
        return Document::fromXmlString($document->toXmlString());
    }

    /**
     * The just-attached ds:SignedInfo, relocated in the reparsed wire. Exactly one exists: this method runs
     * only after the signer attached it, so expectSingle guards an invariant rather than handling input.
     */
    private function locateSignedInfo(Document $document): Element
    {
        return Query::elements($document, '//'.Namespaces::Ds->qualify('SignedInfo'))->expectSingle();
    }

    private function buildSignatureValueElement(Document $document): Element
    {
        return $document->map(namespaced_element(
            Namespaces::Ds->value,
            Namespaces::Ds->qualify('SignatureValue'),
        ));
    }

    private function buildSignature(
        Document $document,
        Element $signedInfo,
        Element $signatureValue,
        Element $keyInfo,
    ): Element {
        return $document->map(namespaced_element(
            Namespaces::Ds->value,
            Namespaces::Ds->qualify('Signature'),
            children(
                static fn (): Element => $signedInfo,
                static fn (): Element => $signatureValue,
                static fn (): Element => $keyInfo,
            ),
        ));
    }
}
