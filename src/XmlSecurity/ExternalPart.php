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
 *
 * The content and the metadata a signature may cover are kept apart rather than handed over pre-joined,
 * because only the content goes through the transform. Joining them first would put the metadata through it
 * too, and for a part whose transform parses its content that is not the same answer.
 */
final readonly class ExternalPart
{
    /**
     * @param non-empty-string         $reference
     * @param non-empty-string         $mimeType
     * @param ResourceStream<resource> $content
     * @param string                   $digestPrefix bytes a signature digests ahead of the content, untouched
     *        by whatever transform the content itself goes through. Empty unless the profile above covers
     *        metadata as well as content
     */
    public function __construct(
        public string $reference,
        public string $mimeType,
        public ResourceStream $content,
        public string $digestPrefix = '',
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
        return new self($this->reference, $mimeType, $content, $this->digestPrefix);
    }
}
