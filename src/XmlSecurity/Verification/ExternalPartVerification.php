<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;

/**
 * The external parts a signature may cover, and the one transform such a reference is required to declare.
 *
 * Presence is the requirement. A verification carrying this accepts a cid: reference; one without it refuses
 * every reference that is not a same-document id, which is the standing rule. The parts here are the only
 * candidates a reference can ever resolve to: nothing is fetched, and a reference naming anything else is
 * refused rather than looked for.
 */
final readonly class ExternalPartVerification
{
    /**
     * @param non-empty-string $transform
     */
    public function __construct(
        public ExternalPartList $parts,
        public string $transform,
    ) {
    }
}
