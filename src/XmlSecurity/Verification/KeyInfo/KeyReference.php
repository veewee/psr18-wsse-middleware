<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo;

/**
 * What a signature's ds:KeyInfo names, as one of the two kinds of key a signature can be verified with: a
 * certificate, named or carried, or a symmetric secret both sides already hold.
 *
 * A closed set of two, because the two are verified by different primitives against different evidence. Which
 * one a message may use is not the resolver's decision: the signature method decides, and pairing an HMAC
 * method with a certificate-resolved key is the algorithm-confusion forgery the orchestrator refuses.
 */
interface KeyReference
{
}
