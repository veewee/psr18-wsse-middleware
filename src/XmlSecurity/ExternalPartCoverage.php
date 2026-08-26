<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

/**
 * How much of an external part a protection covers.
 *
 * A property of the adapter rather than a parameter threaded through the seam. There is then one place a
 * coverage is written, so a block that derived its transform from it could not be paired with an adapter
 * composing parts under a different one.
 *
 * The engine never reads it: the blocks do, to pick the transform or type they declare and demand. It lives
 * here because ExternalParts does and the seam has to be typed.
 */
enum ExternalPartCoverage
{
    /** The part's bytes, and nothing else. */
    case Content;

    /** The part's transport metadata as well as its bytes. */
    case Complete;
}
