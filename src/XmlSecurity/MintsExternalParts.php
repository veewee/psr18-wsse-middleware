<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Phpro\ResourceStream\ResourceStream;

/**
 * An ExternalParts implementation that can also add a part the message did not arrive with.
 *
 * Separate from ExternalParts rather than a method on it, because that seam is public and implemented outside
 * this package: adding to it would break every adapter that exists. Minting is also a different capability
 * from carrying, and only one direction of one feature needs it.
 *
 * The reference comes back rather than going in. Whatever addresses a part is the implementation's vocabulary,
 * so nothing above it invents one: the engine asks for somewhere to put bytes and is told what to point at.
 */
interface MintsExternalParts extends ExternalParts
{
    /**
     * Adds a part carrying these octets and returns it, reference included.
     *
     * @param ResourceStream<resource> $content
     * @param non-empty-string         $mimeType
     */
    public function mint(ResourceStream $content, string $mimeType): ExternalPart;
}
