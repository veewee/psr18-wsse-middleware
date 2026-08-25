<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo;

use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;

/**
 * A ds:Reference matched to the external part it names: the parsed reference data and the caller-supplied part
 * whose octets its digest must reproduce.
 *
 * The part is one the caller handed in on the verification, never something located in the document or
 * retrieved from the URI. That is the whole safety property here: a cid: reference is a lookup in a list the
 * caller controls, so a signature cannot make this package read anything the caller did not already have.
 */
final readonly class ResolvedExternalReference
{
    public function __construct(
        public ParsedReference $parsed,
        public ExternalPart $part,
    ) {
    }
}
