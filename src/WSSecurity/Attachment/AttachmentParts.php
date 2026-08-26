<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Attachment;

use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Attachment\AttachmentsCollection;
use Soap\Psr18AttachmentsMiddleware\Attachment\Cid;
use Soap\Psr18AttachmentsMiddleware\Attachment\IdGenerator;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorageInterface;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\MalformedAttachmentHeaders;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnknownAttachment;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\MintsExternalParts;

/**
 * The shipped ExternalParts implementation over the attachments middleware's storage, so a caller writes no
 * glue at all.
 *
 * It sits beside Part, and the symmetry is the point: Part names the regions of the document to protect,
 * AttachmentParts names the attachment-backed ones, and the two go to withParts() and withAttachments().
 *
 * Named after what it adapts rather than after SwA, because the mechanism is identical under MTOM: both put
 * the bytes in a MIME part addressed by a cid. This is the only class in this package that names the
 * attachments middleware, and the engine below it never hears the word attachment.
 *
 * The coverage is required rather than defaulted. It is not a preference: a peer's policy decides it, both
 * wrong answers are refused by that peer, and a default would let the decision be skipped by someone who
 * never read the WSDL. See docs/attachments.md for the table that turns a policy into this argument.
 */
final readonly class AttachmentParts implements MintsExternalParts
{
    private const OPAQUE_MEDIA_TYPE = 'application/octet-stream';

    private function __construct(
        private AttachmentStorageInterface $storage,
        private AttachmentSide $side,
        private ExternalPartCoverage $coverage,
        private MimeHeaderBlock $headerBlock,
    ) {
    }

    public static function request(
        AttachmentStorageInterface $storage,
        ExternalPartCoverage $coverage,
    ): self {
        AttachmentsPackage::assertSupported();

        return new self($storage, AttachmentSide::Request, $coverage, new MimeHeaderBlock());
    }

    public static function response(
        AttachmentStorageInterface $storage,
        ExternalPartCoverage $coverage,
    ): self {
        AttachmentsPackage::assertSupported();

        return new self($storage, AttachmentSide::Response, $coverage, new MimeHeaderBlock());
    }

    public function coverage(): ExternalPartCoverage
    {
        return $this->coverage;
    }

    public function collect(): ExternalPartList
    {
        return $this->collectEach(
            fn (Attachment $attachment): string => $this->coverage === ExternalPartCoverage::Complete
                ? $this->headerBlock->canonicalize($attachment->headers())
                : '',
        );
    }

    public function collectSealed(): ExternalPartList
    {
        return $this->collectEach(static fn (Attachment $attachment): string => '');
    }

    /**
     * The two collects differ only in what a signature covers besides the content, so they share everything
     * else: the same references, the same media types, and the same rewound streams.
     *
     * @param callable(Attachment): string $digestPrefix
     */
    private function collectEach(callable $digestPrefix): ExternalPartList
    {
        $parts = [];
        foreach ($this->attachments() as $attachment) {
            $parts[] = new ExternalPart(
                reference: Cid::uriFor($attachment->id),
                mimeType: $this->declaredMediaType($attachment),
                // Rewound because a message may be collected twice: sign-then-encrypt digests the plaintext
                // and then seals the same plaintext, and a stream is single-use.
                content: $attachment->content->rewind(),
                digestPrefix: $digestPrefix($attachment),
            );
        }

        return ExternalPartList::of(...$parts);
    }

    /**
     * Adds a part this message did not arrive with, under an id nothing else answers for.
     *
     * The id is generated rather than derived from what the part carries, because two values with the same
     * bytes are still two parts and one id can only address one of them. It stays alphanumeric, which is what
     * keeps a WSS4J peer able to read the reference back: it decodes a cid with a form decoder, so an id
     * holding a plus sign reaches it as a space.
     *
     * @param ResourceStream<resource> $content
     * @param non-empty-string         $mimeType
     */
    public function mint(ResourceStream $content, string $mimeType): ExternalPart
    {
        $attachment = Attachment::cid(
            IdGenerator::generate(),
            'ciphervalue',
            'ciphervalue',
            $content,
            $mimeType,
        );

        $this->attachments()->add($attachment);

        return new ExternalPart(Cid::uriFor($attachment->id), $mimeType, $attachment->content);
    }

    public function replace(ExternalPartList $parts): void
    {
        foreach ($parts as $part) {
            $attachment = $this->attachments()->find(
                static fn (Attachment $attachment): bool => Cid::uriFor($attachment->id) === $part->reference,
            ) ?? throw UnknownAttachment::forReference($part->reference);

            $this->attachments()->replace(
                $this->coverage === ExternalPartCoverage::Complete
                    ? $this->restored($attachment, $part)
                    : $this->reclothed($attachment, $part)
            );
        }
    }

    /**
     * A part whose metadata was covered carries its header set inside its own octets, so the bytes after the
     * blank line are the file and the headers before it are what it travelled as.
     *
     * A set naming another attachment is refused here rather than quietly ignored. The Content-ID is how a
     * reference bound this part to what was covered, so a peer trying to rewrite it from inside the
     * ciphertext is trying to undo that binding.
     */
    private function restored(Attachment $attachment, ExternalPart $part): Attachment
    {
        $decoded = $this->headerBlock->decode($part->content->rewind()->getContents());

        $addressed = $decoded->headers->get('Content-ID');
        if ($addressed !== null && $addressed !== $attachment->id) {
            throw MalformedAttachmentHeaders::addressesAnotherAttachment($addressed, $attachment->id);
        }

        return $attachment
            ->withContent(MemoryStream::create()->write($decoded->content)->rewind(), self::OPAQUE_MEDIA_TYPE)
            ->withHeaders($decoded->headers);
    }

    /**
     * The media type is written back as a header rather than as the scalar, so one carrying a charset comes
     * back whole. A part covered completely by a signature and encrypted content-only is verified against
     * those headers, and an essence string would not reproduce them.
     */
    private function reclothed(Attachment $attachment, ExternalPart $part): Attachment
    {
        // Rewound because the seam that produced this part may already have read it, and what lands here is
        // handed straight to the caller: a spent stream reads as an empty attachment rather than as an error.
        return $attachment
            ->withContent($part->content->rewind(), $part->mimeType)
            ->withHeaders($attachment->headers()->replace('Content-Type', $part->mimeType));
    }

    /**
     * The whole Content-Type header rather than its essence, since that is what a peer restoring this part
     * has to be handed back. The attachments package leaves the media type free-form and defaults it to the
     * opaque type when it cannot name one, so an absent or empty one matches that rather than emitting an
     * empty MimeType attribute.
     *
     * @return non-empty-string
     */
    private function declaredMediaType(Attachment $attachment): string
    {
        $declared = $attachment->headers()->get('Content-Type') ?? $attachment->mimeType;

        return '' === $declared ? self::OPAQUE_MEDIA_TYPE : $declared;
    }

    /**
     * Resolved per call, never captured: AttachmentsMiddleware swaps both collection instances on every
     * request, so an adapter holding one would be stale from the second call onward.
     */
    private function attachments(): AttachmentsCollection
    {
        return $this->side === AttachmentSide::Request
            ? $this->storage->requestAttachments()
            : $this->storage->responseAttachments();
    }
}
