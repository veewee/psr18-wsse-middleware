<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo;

use Dom\Element;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use VeeWee\Xml\Dom\Document;

/**
 * A transform that answers "the element this reference names is an indirection; which element was actually
 * digested?".
 *
 * XML-DSig's own transforms canonicalize the element a reference points at. Some profiles define one that
 * substitutes it first: WS-Security's STR-Transform digests the security token a wsse:SecurityTokenReference
 * names rather than the reference itself. Resolving that needs the profile's vocabulary, which is why it
 * arrives as an SPI rather than living in the engine, exactly as ds:KeyInfo reading does through
 * KeyInfoResolver. The engine contributes what it owns: the reference resolves, and the returned element is
 * checked, under the same hardened id lookup every other reference uses.
 *
 * The two methods are separate because the verifier needs them at different moments. The canonicalization is
 * read first, from the transform element alone, so the algorithm allow-list can refuse the method before the
 * verifier spends any work resolving a reference. Only then is the reference dereferenced.
 *
 * Whatever an implementation throws is collapsed into the caller's uniform failure before it leaves the
 * engine, so a transform cannot become an oracle that tells a peer which shape its reference failed on.
 * Throwing SignatureVerificationFailed directly, with a reason for the operator log, is the intended way to
 * refuse a form the implementation does not reproduce byte-for-byte. Refusing is always the right answer
 * there: a digest computed over an approximation of what the signer digested proves nothing.
 */
interface DereferencingTransform
{
    /**
     * The ds:Transform/@Algorithm this transform claims. A reference declaring it is handed here instead of
     * being refused as an unknown transform.
     *
     * @return non-empty-string
     */
    public function algorithm(): string;

    /**
     * How the element this transform resolves to was canonicalized, read from the transform's own parameters
     * without resolving anything.
     *
     * @param Element $transform the ds:Transform element that declared this algorithm
     *
     * @throws SignatureVerificationFailed when the transform names no canonicalization, or an unreadable one
     */
    public function canonicalization(Element $transform): TransformCanonicalization;

    /**
     * @param Element $referenced the element the reference URI resolved to: the indirection, not the target
     * @param Element $transform  the ds:Transform element that declared this algorithm
     *
     * @throws SignatureVerificationFailed when the indirection cannot be resolved, or names a form this
     *         transform does not reproduce
     */
    public function dereference(
        Document $document,
        Element $referenced,
        Element $transform,
        IdLookup $idLookup,
    ): Element;
}
