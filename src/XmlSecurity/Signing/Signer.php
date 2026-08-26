<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Dom\Element;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\Query;
use Soap\Psr18WsseMiddleware\Xml\XopInclude;
use Soap\Psr18WsseMiddleware\XmlSecurity\AttributeIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\Canonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\InclusivePrefixes;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SigningFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\External\ExternalPartSignature;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\External\SignedExternalParts;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;
use function VeeWee\Xml\Dom\Configurator\disallow_doctype;
use function VeeWee\Xml\Dom\Manipulator\append;

/**
 * Orchestrates the signing flow: resolve Targets to (element, id) pairs (minting ids as needed), digest each
 * element, assemble ds:SignedInfo, canonicalize and sign it, build ds:KeyInfo, then assemble the detached
 * ds:Signature, append it to the container the caller supplies, and re-sort that container.
 *
 * The detached ds:Signature is appended to the container element the caller supplies on the request, so the
 * engine carries no SOAP-header, SOAP-version, or mustUnderstand dependency. The signature is inserted last, so
 * no Target can resolve to it. The private key never leaves the OpenSSL\ boundary: its Key is handed to
 * OpenSSL\Signer, which resolves the live handle internally.
 *
 * Mutates the document in place (id stamps on referenced elements, then ds:Signature insertion).
 */
final class Signer implements XmlSigner
{
    /**
     * The id convention is taken as a pair, not as a minter and a lookup separately: the minter stamps the id
     * and the lookup re-finds it on the reparsed wire, so two that disagree would emit references nobody can
     * follow. Defaults to the engine's xml:id; the WS-Security profile hands over its wsu:Id convention.
     */
    public static function create(?IdConvention $idConvention = null): self
    {
        // The signer and verifier share one canonicalizer instance because digesting and signing read the
        // same canonical form.
        $canonicalizer = new DomCanonicalizer();
        $idConvention ??= AttributeIdConvention::xmlId();
        $idLookup = $idConvention->lookup();

        return new self(
            new ReferenceCollector($idConvention->minter(), new TargetLocator($idLookup)),
            new DigestCalculator($canonicalizer, new Digest()),
            new SignedInfoBuilder(),
            $canonicalizer,
            new OpenSslSigner(),
            $idLookup,
        );
    }

    public function __construct(
        private ReferenceCollector $referenceCollector,
        private DigestCalculator $digestCalculator,
        private SignedInfoBuilder $signedInfoBuilder,
        private Canonicalizer $canonicalizer,
        private OpenSslSigner $opensslSigner,
        private IdLookup $idLookup,
    ) {
    }

    public function sign(Document $document, SigningRequest $request): SignedExternalParts
    {
        $container = $request->container;

        $references = $this->referenceCollector->collect($document, $request->targets);

        $this->assertCoversItsOwnContent($document, $references, $request->externalParts);

        // Digest a fresh parse of the serialized document, not the live DOM. Elements minted with
        // createElementNS carry namespace declarations the live DOM omits but the serialized wire
        // materialises; inclusive C14N folds those declarations into the digest, so digesting the live DOM
        // would produce bytes no verifier reading the wire could reproduce. The reparse is exactly what the
        // wire is, so the digests match across libxml versions.
        $wire = $this->wire($document);

        // A PrefixList parameterizes exclusive C14N only, so an inclusive canonicalization pins nothing even
        // when the caller asked for it. Each list is derived once and then both declared and canonicalized
        // under, which is what keeps a reference's declaration from drifting from its own digest.
        $pinPrefixes = $request->inclusivePrefixes && $request->canonicalization->isExclusive();
        $digests = array_map(
            function (ResolvedReference $reference) use ($wire, $request, $pinPrefixes): SignedReference {
                $element = $this->idLookup->lookup($wire, $reference->id);

                return $this->digestCalculator->forElement(
                    new ResolvedReference($element, $reference->id),
                    $request->canonicalization,
                    $request->digestMethod,
                    $pinPrefixes ? InclusivePrefixes::forSignedElement($element) : [],
                );
            },
            $references,
        );

        // External parts join the same ds:SignedInfo as the in-document references. One signature covering
        // body and attachments together is what a far-side sp:SignedParts policy is checked against; the
        // profile permits several signatures in one header and we do not use that freedom.
        $external = $request->externalParts;
        $covered = ExternalPartList::of();
        if ($external !== null) {
            $covered = $external->parts;
            foreach ($covered as $part) {
                $digests[] = $this->digestCalculator->forExternalPart(
                    $part,
                    $request->digestMethod,
                    $external->transform,
                );
            }
        }

        $signedInfoPrefixes = $pinPrefixes ? InclusivePrefixes::forContainer($request->container) : [];

        $signedInfo = $this->signedInfoBuilder->build(
            $document,
            $request->canonicalization,
            $request->signatureMethod,
            $digests,
            $signedInfoPrefixes,
        );
        $keyInfo = $request->keyIdentifier->apply($document, $request->signingCertificate);

        // The signature is attached first so ds:SignedInfo is in-document: C14N only works on attached nodes,
        // and the signed bytes are the canonical form of SignedInfo as it sits inside the signed message.
        $signatureValue = $this->buildSignatureValueElement($document);
        $signature = $this->buildSignature($document, $signedInfo, $signatureValue, $keyInfo);
        append($signature)($container);

        $this->signInto($signatureValue, $request, $document, $signedInfoPrefixes);

        return new SignedExternalParts($covered);
    }

    /**
     * Canonicalizes ds:SignedInfo from a fresh parse of the now-complete document, signs it, and writes the
     * base64 signature into the ds:SignatureValue element. SignedInfo carries the same live-versus-wire
     * namespace divergence as the signed parts, so the bytes that get signed must be the wire bytes a
     * verifier re-canonicalizes, not the live DOM bytes.
     *
     * @param list<string> $inclusivePrefixes the same list ds:CanonicalizationMethod declares
     *
     * @throws SigningFailed
     */
    private function signInto(
        Element $signatureValue,
        SigningRequest $request,
        Document $document,
        array $inclusivePrefixes,
    ): void {
        $signedInfo = $this->locateSignedInfo($this->wire($document));
        $canonical = $this->canonicalizer->canonicalize(
            $signedInfo,
            $request->canonicalization,
            $inclusivePrefixes === [] ? null : $inclusivePrefixes,
        );

        try {
            $signature = $this->opensslSigner->sign($request->signingKey, $canonical, $request->signatureMethod);
        } catch (OpenSslException $exception) {
            throw SigningFailed::cryptoError($exception->getMessage());
        }

        value(base64_encode($signature))($signatureValue);
    }

    /**
     * Refuses to sign an element that stands in for bytes this signature says nothing about.
     *
     * An xop:Include is a pointer. Digesting the element that holds one produces a signature over the pointer
     * while the bytes it names travel in their own MIME part, and the message still satisfies a far-side
     * policy check for that element being signed. Every reference under a signed element must therefore name
     * one of the external parts this same signature covers, which is the supported MTOM shape.
     *
     * The encryption side refuses the mirror image of this, and the verifier refuses it on the way in.
     *
     * @param list<ResolvedReference> $references
     *
     * @throws SigningFailed
     */
    private function assertCoversItsOwnContent(
        Document $document,
        array $references,
        ?ExternalPartSignature $external,
    ): void {
        foreach ($references as $reference) {
            foreach (XopInclude::hrefsIn($document, $reference->element) as $href) {
                if ($external?->parts->byReference($href) === null) {
                    throw SigningFailed::uncoveredOptimizedContent($href);
                }
            }
        }
    }

    /**
     * The serialized document parsed back into a fresh DOM: exactly the bytes that travel on the wire and the
     * tree a verifier re-canonicalizes from.
     */
    private function wire(Document $document): Document
    {
        return Document::fromXmlString($document->toXmlString(), disallow_doctype());
    }

    /**
     * The just-attached ds:SignedInfo, relocated in the reparsed wire.
     *
     * It is found as the one whose ds:SignatureValue is still empty, because the message may already carry
     * signatures that are none of our business: a SAML assertion issued by a security token service arrives
     * signed by that service, and a document-wide search for ds:SignedInfo finds that one too. The signature
     * being built is the only one whose value has not been written yet, which stays true whatever else the
     * message carries and needs no knowledge of what those other signatures belong to.
     */
    private function locateSignedInfo(Document $document): Element
    {
        return Query::elements(
            $document,
            '//'.Namespaces::Ds->qualify('Signature')
                .'['.Namespaces::Ds->qualify('SignatureValue').'[not(normalize-space())]]'
                .'/'.Namespaces::Ds->qualify('SignedInfo'),
            prefixes: [Namespaces::Ds->prefix() => Namespaces::Ds->uri()],
        )->expectSingle();
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
