<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Phpro\ResourceStream\ResourceStream;

/**
 * One part of the message whose bytes are not in the document, addressed by a URI rather than by an id.
 * The counterpart of a Target: a Target names a region of the document, an external part names bytes the
 * document only points at.
 *
 * The reference is used verbatim, both as the URI to emit and as the key to look a part up by, so this layer
 * neither parses nor builds it. That is what keeps transport vocabulary out of the engine: the profile above
 * decides that a reference happens to be a cid.
 *
 * The same shape serves both directions and both operations. Outbound the content is plaintext, inbound it is
 * ciphertext, and a signature reads it without replacing it.
 */
final readonly class ExternalPart
{
    /**
     * @param non-empty-string         $reference
     * @param non-empty-string         $mimeType
     * @param ResourceStream<resource> $content
     */
    public function __construct(
        public string $reference,
        public string $mimeType,
        public ResourceStream $content,
    ) {
    }

    /**
     * The same part in another representation: the reference still addresses it, so only the bytes and the
     * media type change.
     *
     * @param ResourceStream<resource> $content
     * @param non-empty-string         $mimeType
     */
    public function withContent(ResourceStream $content, string $mimeType): self
    {
        return new self($this->reference, $mimeType, $content);
    }
}
