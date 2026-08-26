<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo;

use Dom\Element;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use VeeWee\Xml\Dom\Document;

/**
 * Reads a signature's ds:KeyInfo into a typed reference to the signer's certificate, without deciding anything
 * about trust. The engine ships the plain XML-DSig reader; a profile supplies its own for the shapes its spec
 * defines, which is how the WS-Security token forms stay out of the engine.
 *
 * The id lookup arrives as an argument rather than being held: an implementation that resolves a token by id must
 * use the same convention the signature's own ds:Reference elements are resolved with, and taking it per call is
 * what stops the two from being configured separately and disagreeing.
 *
 * Whatever an implementation throws is collapsed into SignatureVerificationFailed before it leaves the engine, so
 * a resolver cannot turn into an oracle that tells a peer which shape its ds:KeyInfo failed on. Throwing that
 * type directly, with a reason for the operator log, is the intended way to refuse.
 */
interface KeyInfoResolver
{
    /**
     * @throws SignatureVerificationFailed when ds:KeyInfo carries no reference this resolver recognises, or
     *         carries one that is malformed
     */
    public function read(Document $document, Element $signatureElement, IdLookup $idLookup): CertificateReference;
}
