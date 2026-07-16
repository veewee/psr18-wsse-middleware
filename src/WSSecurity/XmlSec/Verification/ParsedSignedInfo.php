<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;

/**
 * The data read from one ds:SignedInfo: the declared CanonicalizationMethod, the SignatureMethod, and the
 * list of ds:Reference both as parsed values and as the original DOM elements, in the same document order.
 *
 * The reference Elements are carried alongside the parsed values so the resolver can re-read each URI from
 * the exact ds:Reference it belongs to rather than trusting an id parsed elsewhere.
 */
final readonly class ParsedSignedInfo
{
    /**
     * @param list<string> $canonicalizationInclusivePrefixes the exclusive-c14n PrefixList some signers emit on
     *        the CanonicalizationMethod, used when canonicalizing ds:SignedInfo
     * @param non-empty-list<Element> $referenceElements the ds:Reference DOM elements, document order
     * @param non-empty-list<ParsedReference> $references the values parsed from those same references, same order
     */
    public function __construct(
        public SignatureCanonicalization $canonicalization,
        public array $canonicalizationInclusivePrefixes,
        public SignatureMethod $signatureMethod,
        public array $referenceElements,
        public array $references,
    ) {
    }
}
