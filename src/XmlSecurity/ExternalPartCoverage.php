<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

/**
 * How much of an external part a protection covers.
 *
 * A property of the adapter rather than a parameter threaded through the seam, so that a block derives the
 * transform it declares from the same value the adapter composes its parts under. A composition that disagrees
 * with the declared transform is then unrepresentable rather than merely unlikely.
 *
 * The engine never reads this. It lives here because ExternalParts does and the seam has to be typed.
 */
enum ExternalPartCoverage
{
    /** The part's bytes, and nothing else. */
    case Content;

    /** The part's transport metadata as well as its bytes. */
    case Complete;
}
